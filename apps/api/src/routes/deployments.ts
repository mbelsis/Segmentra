import fs from 'node:fs';
import path from 'node:path';

import { Router } from 'express';
import { z } from 'zod';

import { compileHostPolicy } from '@segmentra/compiler';
import { runAnsiblePlaybook, runSshDeployment, type SshHost } from '@segmentra/executor';

import { pool } from '../db/pool.js';
import { env } from '../lib/env.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { readSecretPlaintext } from '../services/secrets.js';

export const deploymentsRouter = Router();
deploymentsRouter.use(requireAuth, requireRole('operator', 'admin'));

const createDeploymentSchema = z.object({
  policyVersionId: z.string().uuid(),
  mode: z.enum(['CANARY', 'PROGRESSIVE', 'FULL']),
  targetQuery: z.object({
    tags: z.array(z.string().uuid()).optional().default([]),
    vlans: z.array(z.string().uuid()).optional().default([]),
    hosts: z.array(z.string().uuid()).optional().default([])
  }),
  canarySize: z.number().int().min(1).optional(),
  batchSize: z.number().int().min(1).optional()
});

async function resolveTargets(q: { tags: string[]; vlans: string[]; hosts: string[] }) {
  const ids = new Set<string>();
  if (q.hosts.length) q.hosts.forEach((x) => ids.add(x));

  if (q.tags.length) {
    const r = await pool.query(
      `SELECT DISTINCT h.id
       FROM hosts h
       JOIN host_tags ht ON ht.host_id=h.id
       WHERE ht.tag_id = ANY($1::uuid[]) AND h.enabled=true`,
      [q.tags]
    );
    r.rows.forEach((x) => ids.add(x.id));
  }

  if (q.vlans.length) {
    const r = await pool.query(`SELECT id FROM hosts WHERE vlan_id = ANY($1::uuid[]) AND enabled=true`, [q.vlans]);
    r.rows.forEach((x) => ids.add(x.id));
  }

  return [...ids];
}

deploymentsRouter.post('/deployments', async (req, res) => {
  const parsed = createDeploymentSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  // Validate that the policy version is APPROVED
  const versionRes = await pool.query(`SELECT status FROM policy_versions WHERE id=$1`, [b.policyVersionId]);
  if (!versionRes.rows[0]) {
    return res.status(404).json({ error: 'policy_version_not_found' });
  }
  if (versionRes.rows[0].status !== 'APPROVED') {
    return res.status(400).json({ 
      error: 'policy_version_not_approved',
      message: `Policy version must be APPROVED to deploy. Current status: ${versionRes.rows[0].status}`
    });
  }

  const targetIds = await resolveTargets(b.targetQuery);
  const { rows } = await pool.query(
    `INSERT INTO deployments (policy_version_id, mode, target_query, target_count, created_by, canary_size, batch_size)
     VALUES ($1,$2,$3,$4,(SELECT id FROM users WHERE username=$5 LIMIT 1),$6,$7)
     RETURNING *`,
    [b.policyVersionId, b.mode, b.targetQuery, targetIds.length, req.auth!.username, b.canarySize ?? null, b.batchSize ?? null]
  );
  const deployment = rows[0];

  for (const hostId of targetIds) {
    await pool.query(`INSERT INTO deployment_hosts (deployment_id, host_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, [
      deployment.id,
      hostId
    ]);
  }

  res.status(201).json({ deployment });
});

deploymentsRouter.get('/deployments', async (_req, res) => {
  const { rows } = await pool.query(`SELECT * FROM deployments ORDER BY created_at DESC`);
  res.json({ deployments: rows });
});

deploymentsRouter.get('/deployments/:deploymentId', async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM deployments WHERE id=$1`, [req.params.deploymentId]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ deployment: rows[0] });
});

deploymentsRouter.get('/deployments/:deploymentId/hosts', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT dh.*, h.hostname, h.mgmt_ip
     FROM deployment_hosts dh
     JOIN hosts h ON h.id = dh.host_id
     WHERE dh.deployment_id=$1
     ORDER BY h.hostname ASC`,
    [req.params.deploymentId]
  );
  res.json({ hosts: rows });
});

deploymentsRouter.get('/deployments/:deploymentId/artifacts', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, bundle_path, bundle_hash, manifest, created_at
     FROM deployment_artifacts
     WHERE deployment_id=$1
     ORDER BY created_at DESC`,
    [req.params.deploymentId]
  );
  res.json({ artifacts: rows });
});

deploymentsRouter.get('/executions/:executionId/logs', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT stdout_path, stderr_path FROM execution_runs WHERE id=$1`,
    [req.params.executionId]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  const stdout = rows[0].stdout_path && fs.existsSync(rows[0].stdout_path) ? fs.readFileSync(rows[0].stdout_path, 'utf8') : '';
  const stderr = rows[0].stderr_path && fs.existsSync(rows[0].stderr_path) ? fs.readFileSync(rows[0].stderr_path, 'utf8') : '';
  res.json({ stdout, stderr });
});

async function generateBundle(deploymentId: string) {
  const bundleDir = path.join(env.BUNDLES_DIR, deploymentId);
  const hostRulesDir = path.join(bundleDir, 'host_rules');
  fs.mkdirSync(hostRulesDir, { recursive: true });

  const depRes = await pool.query(`SELECT * FROM deployments WHERE id=$1`, [deploymentId]);
  const dep = depRes.rows[0];
  if (!dep) throw new Error('deployment_not_found');

  const hostRows = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM deployment_hosts dh
     JOIN hosts h ON h.id = dh.host_id
     WHERE dh.deployment_id=$1`,
    [deploymentId]
  );

  const vRes = await pool.query(
    `SELECT interface_scope_type, interface_scope_roles, interface_scope_names
     FROM policy_versions WHERE id=$1`,
    [dep.policy_version_id]
  );
  const v = vRes.rows[0];
  if (!v) throw new Error('policy_version_not_found');

  const rRes = await pool.query(
    `SELECT order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment,
            use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names
     FROM policy_rules
     WHERE policy_version_id=$1`,
    [dep.policy_version_id]
  );

  const policyInterfaceScope =
    v.interface_scope_type === 'ALL_INTERFACES'
      ? { type: 'ALL_INTERFACES' as const }
      : v.interface_scope_type === 'INTERFACE_NAME'
        ? { type: 'INTERFACE_NAME' as const, names: (v.interface_scope_names ?? []) as string[] }
        : { type: 'INTERFACE_ROLE' as const, roles: (v.interface_scope_roles ?? []) as string[] };

  // resolved sets shared across hosts
  const sets: Record<string, string[]> = {};
  for (const rule of rRes.rows as any[]) {
    if (rule.source_type === 'CIDR') continue;
    const setName = `src_${rule.source_type.toLowerCase()}_${String(rule.source_value).replace(/-/g, '')}`;
    if (sets[setName]) continue;

    let ips: string[] = [];
    if (rule.source_type === 'HOST') {
      const h = await pool.query(`SELECT mgmt_ip FROM hosts WHERE id=$1`, [rule.source_value]);
      if (h.rows[0]?.mgmt_ip) ips = [String(h.rows[0].mgmt_ip)];
    } else if (rule.source_type === 'TAG') {
      const q = await pool.query(
        `SELECT h.mgmt_ip FROM hosts h
         JOIN host_tags ht ON ht.host_id=h.id
         WHERE ht.tag_id=$1 AND h.mgmt_ip IS NOT NULL AND h.enabled=true`,
        [rule.source_value]
      );
      ips = q.rows.map((x) => String(x.mgmt_ip));
    } else if (rule.source_type === 'VLAN') {
      const q = await pool.query(
        `SELECT mgmt_ip FROM hosts WHERE vlan_id=$1 AND mgmt_ip IS NOT NULL AND enabled=true`,
        [rule.source_value]
      );
      ips = q.rows.map((x) => String(x.mgmt_ip));
    }
    sets[setName] = ips;
  }

  const manifest = {
    deployment_id: deploymentId,
    policy_version_id: dep.policy_version_id,
    interface_scope: policyInterfaceScope,
    target_count: dep.target_count
  };
  fs.writeFileSync(path.join(bundleDir, 'manifest.json'), JSON.stringify(manifest, null, 2));

  // pick GLOBAL ssh credential for v1
  const credRes = await pool.query(
    `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
  );
  const cred = credRes.rows[0];
  if (!cred) throw new Error('missing_ssh_credential');
  const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
  const keyPath = path.join(bundleDir, 'ssh_key');
  fs.writeFileSync(keyPath, keyPem, { encoding: 'utf8' });

  const inventoryLines: string[] = ['[all]'];

  for (const h of hostRows.rows as any[]) {
    const ifsRes = await pool.query(`SELECT name, role, enabled FROM host_interfaces WHERE host_id=$1`, [h.id]);
    const backend = h.firewall_backend === 'iptables' ? 'iptables' : 'nftables';

    const rules = (rRes.rows as any[]).map((r) => {
      const ruleScope =
        r.interface_scope_type === 'ALL_INTERFACES'
          ? { type: 'ALL_INTERFACES' as const }
          : r.interface_scope_type === 'INTERFACE_NAME'
            ? { type: 'INTERFACE_NAME' as const, names: (r.interface_scope_names ?? []) as string[] }
            : r.interface_scope_type === 'INTERFACE_ROLE'
              ? { type: 'INTERFACE_ROLE' as const, roles: (r.interface_scope_roles ?? []) as string[] }
              : undefined;
      const remote = r.source_type === 'CIDR'
        ? ({ kind: 'CIDR' as const })
        : ({ kind: 'SET' as const, setName: `src_${r.source_type.toLowerCase()}_${String(r.source_value).replace(/-/g, '')}` });
      return {
        orderIndex: Number(r.order_index),
        direction: (r.direction ?? 'IN') as 'IN' | 'OUT' | 'BOTH',
        action: r.action,
        protocol: r.protocol,
        ports: r.ports,
        sourceType: r.source_type,
        sourceValue: r.source_value,
        logMode: r.log_mode,
        comment: r.comment,
        usePolicyInterfaceScope: Boolean(r.use_policy_interface_scope),
        interfaceScope: ruleScope,
        remote
      };
    });

    const compiled = compileHostPolicy({
      host: {
        id: h.id,
        hostname: h.hostname,
        mgmtIp: h.mgmt_ip ? String(h.mgmt_ip) : null,
        firewallBackend: backend,
        interfaces: ifsRes.rows.map((i: any) => ({ name: i.name, role: i.role, enabled: i.enabled }))
      },
      policyInterfaceScope,
      rules,
      sets,
      baseline: { mgmtSshCidrs: ['10.0.0.0/8'] }
    });

    const ext = compiled.backend === 'nftables' ? 'nft' : 'iptables';
    const policyFileHostPath = path.join(hostRulesDir, `${h.hostname}.${ext}`);
    fs.writeFileSync(policyFileHostPath, compiled.text, 'utf8');

    // Ansible runner sees bundle at /bundles/<deploymentId>/...
    const policyFileRunnerPath = `/bundles/${deploymentId}/host_rules/${h.hostname}.${ext}`;

    inventoryLines.push(
      `${h.hostname} ansible_host=${String(h.mgmt_ip)} ansible_port=${h.ssh_port} ansible_user=${cred.username} ansible_ssh_private_key_file=/bundles/${deploymentId}/ssh_key ansible_become=yes ansible_become_method=sudo segmentra_policy_file=${policyFileRunnerPath}`
    );
  }

  fs.writeFileSync(path.join(bundleDir, 'inventory.ini'), inventoryLines.join('\n') + '\n', 'utf8');

  // artifacts row (bundle hash omitted v1)
  await pool.query(
    `INSERT INTO deployment_artifacts (deployment_id, bundle_path, bundle_hash, manifest)
     VALUES ($1,$2,$3,$4)`,
    [deploymentId, bundleDir, 'todo', manifest]
  );

  return { bundleDir };
}

deploymentsRouter.post('/deployments/:deploymentId/start', async (req, res) => {
  const deploymentId = req.params.deploymentId;

  await pool.query(`UPDATE deployments SET status='RUNNING', started_at=now() WHERE id=$1`, [deploymentId]);
  await pool.query(`UPDATE deployment_hosts SET status='RUNNING', started_at=now() WHERE deployment_id=$1`, [
    deploymentId
  ]);

  const { bundleDir } = await generateBundle(deploymentId);

  // Get executor setting
  const executorRes = await pool.query(
    `SELECT value FROM system_settings WHERE key='deployment_executor'`
  );
  const executor = executorRes.rows[0]?.value ?? 'ansible';

  const stdoutPath = path.join(bundleDir, executor === 'ssh' ? 'ssh.stdout.log' : 'ansible.stdout.log');
  const stderrPath = path.join(bundleDir, executor === 'ssh' ? 'ssh.stderr.log' : 'ansible.stderr.log');

  let ok = false;
  let exitCode = 1;
  let executionId: string;

  if (executor === 'ssh') {
    // SSH Direct executor
    const executionIdRes = await pool.query(
      `INSERT INTO execution_runs (deployment_id, executor_type, command)
       VALUES ($1,'ssh_direct',$2)
       RETURNING id`,
      [deploymentId, 'ssh/scp direct execution']
    );
    executionId = executionIdRes.rows[0].id;

    // Get SSH credential
    const credRes = await pool.query(
      `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
    );
    const cred = credRes.rows[0];
    if (!cred) {
      await pool.query(`UPDATE execution_runs SET status='DONE', finished_at=now() WHERE id=$1`, [executionId]);
      await pool.query(`UPDATE deployments SET status='FAILED', finished_at=now() WHERE id=$1`, [deploymentId]);
      return res.status(400).json({ error: 'missing_ssh_credential' });
    }

    const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
    const keyPath = path.join(bundleDir, 'ssh_key');
    fs.writeFileSync(keyPath, keyPem, { encoding: 'utf8', mode: 0o600 });

    // Get hosts and policy files
    const hostRows = await pool.query(
      `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
       FROM deployment_hosts dh
       JOIN hosts h ON h.id = dh.host_id
       WHERE dh.deployment_id=$1`,
      [deploymentId]
    );

    const sshHosts: SshHost[] = [];
    for (const h of hostRows.rows as any[]) {
      const backend = h.firewall_backend === 'iptables' ? 'iptables' : 'nftables';
      const ext = backend === 'nftables' ? 'nft' : 'iptables';
      const policyFilePath = path.join(bundleDir, 'host_rules', `${h.hostname}.${ext}`);
      
      if (fs.existsSync(policyFilePath)) {
        sshHosts.push({
          hostname: h.hostname,
          ip: String(h.mgmt_ip),
          port: h.ssh_port || 22,
          username: cred.username,
          privateKeyPath: keyPath,
          policyFilePath,
          backend
        });
      }
    }

    const results = await runSshDeployment({
      hosts: sshHosts,
      stdoutPath,
      stderrPath
    });

    // Update deployment_hosts based on results
    const failedHosts = results.filter(r => !r.success);
    ok = failedHosts.length === 0;
    exitCode = ok ? 0 : 1;

    for (const result of results) {
      const host = hostRows.rows.find((h: any) => h.hostname === result.hostname);
      if (host) {
        await pool.query(
          `UPDATE deployment_hosts
           SET status=$2, finished_at=now(), message=$3
           WHERE deployment_id=$1 AND host_id=$4`,
          [deploymentId, result.success ? 'SUCCEEDED' : 'FAILED', result.success ? 'ok' : 'ssh_failed', host.id]
        );
      }
    }

    await pool.query(
      `UPDATE execution_runs
       SET exit_code=$2, stdout_path=$3, stderr_path=$4, finished_at=now(), status='DONE'
       WHERE id=$1`,
      [executionId, exitCode, stdoutPath, stderrPath]
    );
  } else {
    // Ansible executor (default)
    const executionIdRes = await pool.query(
      `INSERT INTO execution_runs (deployment_id, executor_type, command)
       VALUES ($1,'ansible_cli',$2)
       RETURNING id`,
      [deploymentId, 'docker exec ... ansible-playbook']
    );
    executionId = executionIdRes.rows[0].id;

    const result = await runAnsiblePlaybook({
      runnerContainer: env.ANSIBLE_RUNNER_CONTAINER,
      inventoryPath: `/bundles/${deploymentId}/inventory.ini`,
      playbookPath: `/runner/playbooks/apply-firewall.yml`,
      stdoutPath,
      stderrPath
    });

    exitCode = result.exitCode;
    ok = exitCode === 0;

    await pool.query(
      `UPDATE execution_runs
       SET exit_code=$2, stdout_path=$3, stderr_path=$4, finished_at=now(), status='DONE'
       WHERE id=$1`,
      [executionId, exitCode, stdoutPath, stderrPath]
    );

    await pool.query(
      `UPDATE deployment_hosts
       SET status=$2, finished_at=now(), message=$3
       WHERE deployment_id=$1`,
      [deploymentId, ok ? 'SUCCEEDED' : 'FAILED', ok ? 'ok' : 'ansible_failed']
    );
  }

  await pool.query(
    `UPDATE deployments SET status=$2, finished_at=now() WHERE id=$1`,
    [deploymentId, ok ? 'SUCCEEDED' : 'FAILED']
  );

  res.json({ ok, exitCode, executionId });
});

deploymentsRouter.post('/deployments/:deploymentId/cancel', async (req, res) => {
  // v1: best-effort cancellation (no process tracking yet)
  await pool.query(`UPDATE deployments SET status='CANCELLED', finished_at=now() WHERE id=$1 AND status='RUNNING'`, [
    req.params.deploymentId
  ]);
  await pool.query(`UPDATE deployment_hosts SET status='SKIPPED', finished_at=now() WHERE deployment_id=$1 AND status='PENDING'`, [
    req.params.deploymentId
  ]);
  res.json({ ok: true });
});

deploymentsRouter.post('/deployments/:deploymentId/retry-failed', async (req, res) => {
  await pool.query(`UPDATE deployment_hosts SET status='PENDING', started_at=null, finished_at=null, message=null WHERE deployment_id=$1 AND status='FAILED'`, [
    req.params.deploymentId
  ]);
  res.json({ ok: true });
});


