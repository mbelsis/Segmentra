/**
 * Automated inventory discovery.
 *
 * A profile has one or more target sets (SSH credential + IPv4 networks + SSH port).
 * A run expands the networks, TCP-probes the SSH port, logs in with the target set's
 * credential(s), collects read-only facts and imports new hosts into inventory.
 *
 * Limits: IPv4 only; each network entry at most /20 (4096 addresses); a whole run at
 * most 8192 unique addresses. Validated at save time and again at run time (VLAN
 * subnets can change after a profile was saved).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';

import {
  discoverHostOverSsh,
  mapWithConcurrency,
  probeTcpPort,
  type DiscoveredHostFacts
} from '@segmentra/executor';

import { pool } from '../db/pool.js';
import { createAuditEvent } from './audit.js';
import { EFFECTIVE_CREDENTIAL_LATERAL, materializeSshCredential, sshAuthFields, type MaterializedSshCredential } from './ssh-credentials.js';
import { evaluateHostAgainstRules } from './tag-rule-engine.js';
import { triggerTemplateAutoApply } from './template-engine.js';

export const MAX_ADDRESSES_PER_NETWORK = 4096; // /20
export const MIN_IPV4_PREFIX = 20;
export const MAX_ADDRESSES_PER_RUN = 8192;
export const MAX_RESULT_ENTRIES = 2000;
const PROBE_CONCURRENCY = 64;
const PROBE_TIMEOUT_MS = 1500;
const LOGIN_CONCURRENCY = 16;
const LOGIN_TIMEOUT_MS = 30_000;
/** A RUNNING run older than this is considered abandoned (process crash) and marked FAILED. */
const STALE_RUN_HOURS = 6;

// ---------------------------------------------------------------- IPv4 helpers

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0);
}

function intToIpv4(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

export type ParsedIpv4Network = { network: number; prefix: number; cidr: string };

/** Parse "10.0.0.0/24" or a bare "10.0.0.5" (=/32). Host bits are cleared. Returns an error string on failure. */
export function parseIpv4Network(value: string): ParsedIpv4Network | { error: string } {
  const trimmed = String(value ?? '').trim();
  const [ip, prefixPart, extra] = trimmed.split('/');
  if (extra !== undefined || !ip) return { error: `"${trimmed}" is not a valid IPv4 CIDR` };
  if (net.isIP(ip) === 6) return { error: `"${trimmed}" is IPv6; discovery supports IPv4 only` };
  if (net.isIP(ip) !== 4) return { error: `"${trimmed}" is not a valid IPv4 address or CIDR` };
  let prefix = 32;
  if (prefixPart !== undefined) {
    if (!/^\d{1,2}$/.test(prefixPart) || Number(prefixPart) > 32) return { error: `"${trimmed}" has an invalid prefix length` };
    prefix = Number(prefixPart);
  }
  if (prefix < MIN_IPV4_PREFIX) {
    return {
      error: `${trimmed} is too large: ${2 ** (32 - prefix)} addresses (each network may be at most /${MIN_IPV4_PREFIX} = ${MAX_ADDRESSES_PER_NETWORK} addresses)`
    };
  }
  const size = 2 ** (32 - prefix);
  const network = Math.floor(ipv4ToInt(ip) / size) * size;
  return { network, prefix, cidr: `${intToIpv4(network)}/${prefix}` };
}

/** Host addresses of a network. Network/broadcast are skipped for /30 and larger; /31 and /32 use every address. */
export function expandIpv4Network(n: ParsedIpv4Network): string[] {
  const size = 2 ** (32 - n.prefix);
  const out: string[] = [];
  const skipEdges = n.prefix <= 30;
  for (let i = skipEdges ? 1 : 0; i < (skipEdges ? size - 1 : size); i++) out.push(intToIpv4(n.network + i));
  return out;
}

// ---------------------------------------------------------------- target resolution / validation

export type DiscoveryTargetInput = {
  sshCredentialId: string;
  sshPort: number;
  cidrs: string[];
  vlanIds: string[];
};

export type ResolvedTarget = DiscoveryTargetInput & {
  index: number;
  /** Normalised networks actually scanned (typed CIDRs + VLAN subnets). */
  networks: string[];
  addresses: string[];
};

/**
 * Validate target sets and expand them into addresses. Returns human-readable problems
 * (empty when valid) plus the expansion. Problems are prefixed with the target set number.
 */
export async function resolveTargets(
  targets: DiscoveryTargetInput[],
  opts: { strictVlans: boolean } = { strictVlans: true }
): Promise<{ problems: string[]; warnings: string[]; resolved: ResolvedTarget[]; uniqueAddressCount: number }> {
  const problems: string[] = [];
  const warnings: string[] = [];
  const resolved: ResolvedTarget[] = [];

  const credIds = [...new Set(targets.map((t) => t.sshCredentialId))];
  const vlanIds = [...new Set(targets.flatMap((t) => t.vlanIds))];
  const { rows: creds } = credIds.length
    ? await pool.query(`SELECT id FROM ssh_credentials WHERE id = ANY($1::uuid[])`, [credIds])
    : { rows: [] as any[] };
  const knownCreds = new Set(creds.map((c: any) => String(c.id)));
  const { rows: vlans } = vlanIds.length
    ? await pool.query(`SELECT id, vlan_tag, name, subnet FROM vlans WHERE id = ANY($1::uuid[])`, [vlanIds])
    : { rows: [] as any[] };
  const vlanById = new Map<string, any>(vlans.map((v: any) => [String(v.id), v]));

  const all = new Set<string>();
  targets.forEach((t, index) => {
    const label = `Target set ${index + 1}`;
    if (!knownCreds.has(t.sshCredentialId)) problems.push(`${label}: SSH credential not found`);
    const networks: string[] = [];
    for (const c of t.cidrs) {
      const p = parseIpv4Network(c);
      if ('error' in p) problems.push(`${label}: ${p.error}`);
      else networks.push(p.cidr);
    }
    for (const vid of t.vlanIds) {
      const v = vlanById.get(vid);
      const report = (msg: string) => (opts.strictVlans ? problems : warnings).push(`${label}: ${msg}`);
      if (!v) { report(`VLAN ${vid} not found`); continue; }
      const vname = `VLAN ${v.vlan_tag} (${v.name})`;
      if (!v.subnet) { report(`${vname} has no subnet configured`); continue; }
      const p = parseIpv4Network(String(v.subnet));
      if ('error' in p) problems.push(`${label}: ${vname}: ${p.error}`);
      else networks.push(p.cidr);
    }
    if (t.cidrs.length === 0 && t.vlanIds.length === 0) problems.push(`${label}: add at least one network (CIDR or VLAN)`);
    const uniqNetworks = [...new Set(networks)];
    const addrSet = new Set<string>();
    for (const n of uniqNetworks) {
      const p = parseIpv4Network(n) as ParsedIpv4Network;
      for (const a of expandIpv4Network(p)) addrSet.add(a);
    }
    const addresses = [...addrSet];
    addresses.forEach((a) => all.add(a));
    resolved.push({ ...t, index, networks: uniqNetworks, addresses });
  });

  if (all.size > MAX_ADDRESSES_PER_RUN) {
    problems.push(`The profile covers ${all.size} addresses; a discovery run may scan at most ${MAX_ADDRESSES_PER_RUN}. Split it into several profiles.`);
  }
  return { problems, warnings, resolved, uniqueAddressCount: all.size };
}

// ---------------------------------------------------------------- run lifecycle

export class DiscoveryAlreadyRunningError extends Error {
  constructor() {
    super('discovery_already_running');
  }
}

export type DiscoveryAddressResult = {
  ip: string;
  port?: number;
  status: 'imported' | 'already_present' | 'login_failed' | 'error';
  hostname?: string;
  hostId?: string;
  credentialName?: string;
  osPrettyName?: string | null;
  firewallBackend?: string;
  sudo?: string;
  reason?: string;
  warnings?: string[];
};

type Counts = {
  addressesScanned: number;
  sshOpen: number;
  loginOk: number;
  imported: number;
  alreadyPresent: number;
  loginFailed: number;
};

/**
 * Start a run for a profile. Inserts the RUNNING row synchronously (the partial unique
 * index guarantees at most one RUNNING run per profile) and executes it in the background.
 */
export async function startDiscoveryRun(profileId: string, trigger: 'manual' | 'scheduled', actorUserId: string | null): Promise<{ runId: string }> {
  let runId: string;
  try {
    const { rows } = await pool.query(
      `INSERT INTO discovery_runs (profile_id, trigger, status, created_by)
       VALUES ($1, $2, 'RUNNING', $3) RETURNING id`,
      [profileId, trigger, actorUserId]
    );
    runId = rows[0].id;
  } catch (e: any) {
    if (e?.code === '23505') throw new DiscoveryAlreadyRunningError();
    throw e;
  }
  void executeRun(runId, profileId, trigger, actorUserId).catch((e) => {
    // eslint-disable-next-line no-console
    console.error(`[Discovery] Run ${runId} crashed:`, e);
  });
  return { runId };
}

function sanitizeHostname(raw: string, ip: string): string {
  const cleaned = String(raw ?? '').trim().replace(/[^A-Za-z0-9._-]/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 200);
  return cleaned || `host-${ip.replace(/\./g, '-')}`;
}

function pickBackend(f: DiscoveredHostFacts): 'nftables' | 'iptables' | 'auto' {
  if (f.hasFirewallManager) return 'auto';
  if (f.hasNft) return 'nftables';
  if (f.hasIptablesRestore) return 'iptables';
  return 'auto';
}

async function finishRun(runId: string, status: 'SUCCEEDED' | 'FAILED', counts: Counts, results: DiscoveryAddressResult[], error: string | null) {
  await pool.query(
    `UPDATE discovery_runs
        SET status = $2, finished_at = now(), addresses_scanned = $3, ssh_open = $4, login_ok = $5,
            imported = $6, already_present = $7, login_failed = $8, results = $9::jsonb, error = $10
      WHERE id = $1`,
    [runId, status, counts.addressesScanned, counts.sshOpen, counts.loginOk, counts.imported, counts.alreadyPresent, counts.loginFailed,
      JSON.stringify(results.slice(0, MAX_RESULT_ENTRIES)), error]
  );
}

async function executeRun(runId: string, profileId: string, trigger: 'manual' | 'scheduled', actorUserId: string | null): Promise<void> {
  const counts: Counts = { addressesScanned: 0, sshOpen: 0, loginOk: 0, imported: 0, alreadyPresent: 0, loginFailed: 0 };
  const results: DiscoveryAddressResult[] = [];
  const materialized = new Map<string, Promise<MaterializedSshCredential>>();
  const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'segmentra-discovery-'));
  let status: 'SUCCEEDED' | 'FAILED' = 'SUCCEEDED';
  let error: string | null = null;
  let profileName = '';

  try {
    const { rows: profiles } = await pool.query(`SELECT * FROM discovery_profiles WHERE id = $1`, [profileId]);
    const profile = profiles[0];
    if (!profile) throw new Error('profile not found');
    profileName = profile.name;
    const { rows: targetRows } = await pool.query(
      `SELECT * FROM discovery_targets WHERE profile_id = $1 ORDER BY position, created_at`,
      [profileId]
    );
    const targets: DiscoveryTargetInput[] = targetRows.map((t: any) => ({
      sshCredentialId: String(t.ssh_credential_id),
      sshPort: Number(t.ssh_port),
      cidrs: t.cidrs ?? [],
      vlanIds: (t.vlan_ids ?? []).map(String)
    }));
    if (targets.length === 0) throw new Error('profile has no target sets');
    const { problems, warnings, resolved } = await resolveTargets(targets, { strictVlans: false });
    if (problems.length) throw new Error(problems.join('; '));
    if (warnings.length) {
      // eslint-disable-next-line no-console
      console.warn(`[Discovery] ${profile.name}: ${warnings.join('; ')}`);
    }

    const { rows: credRows } = await pool.query(
      `SELECT * FROM ssh_credentials WHERE id = ANY($1::uuid[])`,
      [[...new Set(targets.map((t) => t.sshCredentialId))]]
    );
    const credById = new Map<string, any>(credRows.map((c: any) => [String(c.id), c]));

    // ip -> ordered candidate (target set) list
    const candidatesByIp = new Map<string, ResolvedTarget[]>();
    for (const t of resolved) {
      for (const a of t.addresses) {
        const list = candidatesByIp.get(a) ?? [];
        list.push(t);
        candidatesByIp.set(a, list);
      }
    }
    counts.addressesScanned = candidatesByIp.size;

    // 1) TCP probe each unique (ip, port)
    const probeKeys = new Set<string>();
    for (const [ip, list] of candidatesByIp) for (const t of list) probeKeys.add(`${ip}|${t.sshPort}`);
    const probeList = [...probeKeys];
    const probeResults = await mapWithConcurrency(probeList, PROBE_CONCURRENCY, async (k) => {
      const [ip, port] = k.split('|');
      return probeTcpPort(ip, Number(port), PROBE_TIMEOUT_MS);
    });
    const openKeys = new Set(probeList.filter((_, i) => probeResults[i]));
    const openIps = [...candidatesByIp.keys()].filter((ip) => candidatesByIp.get(ip)!.some((t) => openKeys.has(`${ip}|${t.sshPort}`)));
    counts.sshOpen = openIps.length;

    // 2) Skip addresses already in inventory (no login attempted against them)
    const { rows: existing } = openIps.length
      ? await pool.query(`SELECT id, hostname, host(mgmt_ip) AS ip FROM hosts WHERE host(mgmt_ip) = ANY($1::text[])`, [openIps])
      : { rows: [] as any[] };
    const existingByIp = new Map<string, any>(existing.map((h: any) => [String(h.ip), h]));

    const loginIps = openIps.filter((ip) => {
      const h = existingByIp.get(ip);
      if (!h) return true;
      counts.alreadyPresent++;
      results.push({ ip, status: 'already_present', hostname: h.hostname, hostId: h.id, reason: 'already in inventory' });
      return false;
    });

    const getCred = (credId: string) => {
      let p = materialized.get(credId);
      if (!p) {
        p = materializeSshCredential(credById.get(credId), keyDir);
        materialized.set(credId, p);
      }
      return p;
    };

    // 3) Log in (try each covering target set's credential in order) and import
    // The default tag is created on first use (only when something is actually imported).
    let tagIdPromise: Promise<string> | null = null;
    const getTagId = () => {
      tagIdPromise ??= pool.query(
        `WITH ins AS (INSERT INTO tags (name, description) VALUES ($1, 'Applied by inventory discovery') ON CONFLICT (name) DO NOTHING RETURNING id)
         SELECT id FROM ins UNION ALL SELECT id FROM tags WHERE name = $1 LIMIT 1`,
        [profile.default_tag_name]
      ).then((r) => String(r.rows[0].id));
      return tagIdPromise;
    };

    const loginOutcomes = await mapWithConcurrency(loginIps, LOGIN_CONCURRENCY, async (ip): Promise<DiscoveryAddressResult> => {
      const tried = new Set<string>();
      const failures: string[] = [];
      for (const t of candidatesByIp.get(ip)!) {
        if (!openKeys.has(`${ip}|${t.sshPort}`)) continue;
        const key = `${t.sshCredentialId}|${t.sshPort}`;
        if (tried.has(key)) continue;
        tried.add(key);
        const credRow = credById.get(t.sshCredentialId);
        if (!credRow) { failures.push('credential missing'); continue; }
        let mat: MaterializedSshCredential;
        try {
          mat = await getCred(t.sshCredentialId);
        } catch (e: any) {
          failures.push(`${credRow.name}: cannot decrypt credential (${e?.message ?? e})`);
          continue;
        }
        const r = await discoverHostOverSsh(
          {
            ip,
            port: t.sshPort,
            ...sshAuthFields(mat)
          },
          { timeoutMs: LOGIN_TIMEOUT_MS }
        );
        if (!r.ok) {
          failures.push(candidatesByIp.get(ip)!.length > 1 ? `${credRow.name}: ${r.message}` : r.message);
          continue;
        }
        counts.loginOk++;
        try {
          return await importHost({ ip, port: t.sshPort, facts: r.facts, credRow, tagId: await getTagId(), profileName: profile.name });
        } catch (e: any) {
          return { ip, port: t.sshPort, status: 'error', credentialName: credRow.name, reason: `import failed: ${e?.message ?? e}` };
        }
      }
      counts.loginFailed++;
      return { ip, status: 'login_failed', reason: failures.join('; ') || 'no usable credential' };
    });

    for (const r of loginOutcomes) {
      if (r.status === 'imported') counts.imported++;
      if (r.status === 'already_present') counts.alreadyPresent++;
      results.push(r);
    }
    results.sort((a, b) => ipv4ToInt(a.ip) - ipv4ToInt(b.ip));
  } catch (e: any) {
    status = 'FAILED';
    error = String(e?.message ?? e).slice(0, 2000);
  } finally {
    for (const p of materialized.values()) {
      p.then((m) => m.cleanup()).catch(() => {});
    }
    try { fs.rmSync(keyDir, { recursive: true, force: true }); } catch { /* best effort */ }
  }

  await finishRun(runId, status, counts, results, error);
  await pool.query(
    `UPDATE discovery_profiles
        SET last_run_at = now(),
            next_run_at = CASE WHEN schedule_interval_minutes IS NULL THEN NULL
                               ELSE now() + make_interval(mins => schedule_interval_minutes) END
      WHERE id = $1`,
    [profileId]
  );
  await createAuditEvent({
    actorUserId,
    action: status === 'SUCCEEDED' ? 'DISCOVERY_RUN_COMPLETED' : 'DISCOVERY_RUN_FAILED',
    entityType: 'discovery_run',
    entityId: runId,
    metadata: { profileId, profileName, trigger, ...counts, ...(error ? { error } : {}) }
  }).catch((e) => {
    // eslint-disable-next-line no-console
    console.error('[Discovery] Failed to write audit event:', e);
  });
  // eslint-disable-next-line no-console
  console.log(`[Discovery] ${profileName || profileId} (${trigger}) ${status}: scanned=${counts.addressesScanned} open=${counts.sshOpen} loginOk=${counts.loginOk} imported=${counts.imported} present=${counts.alreadyPresent} loginFailed=${counts.loginFailed}`);
}

async function importHost(params: {
  ip: string;
  port: number;
  facts: DiscoveredHostFacts;
  credRow: any;
  tagId: string;
  profileName: string;
}): Promise<DiscoveryAddressResult> {
  const { ip, port, facts, credRow } = params;
  const warnings: string[] = [];
  const sudoWarnings: Partial<Record<DiscoveredHostFacts['sudo'], string>> = {
    none: 'no usable sudo for this account (deployments to this host will fail until sudo is configured)',
    password_required:
      'sudo requires a password, but the credential is set to "sudo without password" (set its privilege escalation to "sudo with the login password" or "sudo with a separate password")',
    password_rejected: "sudo rejected the credential's sudo password",
    tty_required: 'sudo requires a terminal (Defaults requiretty); disable requiretty for this account'
  };
  const sudoWarning = sudoWarnings[facts.sudo];
  if (sudoWarning) warnings.push(sudoWarning);
  const backend = pickBackend(facts);
  if (backend === 'auto' && !facts.hasFirewallManager) warnings.push('neither nft nor iptables-restore found');

  const client = await pool.connect();
  let hostId: string;
  let hostname: string;
  try {
    await client.query('BEGIN');
    // Serialise imports of the same address across concurrent runs of different profiles.
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [`segmentra-discovery-ip:${ip}`]);
    const { rows: dup } = await client.query(`SELECT id, hostname FROM hosts WHERE host(mgmt_ip) = $1 LIMIT 1`, [ip]);
    if (dup[0]) {
      await client.query('ROLLBACK');
      return { ip, port, status: 'already_present', hostname: dup[0].hostname, hostId: dup[0].id, reason: 'already in inventory' };
    }

    const base = sanitizeHostname(facts.hostname, ip);
    const lastOctet = ip.split('.').pop();
    const candidates = [base, `${base}-${lastOctet}`, `${base}-${ip.replace(/\./g, '-')}`];
    hostname = '';
    for (const c of candidates) {
      const { rows } = await client.query(`SELECT 1 FROM hosts WHERE hostname = $1`, [c]);
      if (!rows[0]) { hostname = c; break; }
    }
    for (let i = 2; !hostname; i++) {
      const c = `${base}-${ip.replace(/\./g, '-')}-${i}`;
      const { rows } = await client.query(`SELECT 1 FROM hosts WHERE hostname = $1`, [c]);
      if (!rows[0]) hostname = c;
    }

    const { rows: inserted } = await client.query(
      `INSERT INTO hosts (hostname, mgmt_ip, ssh_port, os_family, firewall_backend, enabled)
       VALUES ($1, $2, $3, $4, $5, true) RETURNING id`,
      [hostname, ip, port, facts.osId, backend]
    );
    hostId = inserted[0].id;
    await client.query(
      `INSERT INTO host_tags (host_id, tag_id, source) VALUES ($1, $2, 'manual') ON CONFLICT DO NOTHING`,
      [hostId, params.tagId]
    );
    // Make deployments use the credential that worked: unless automatic scope resolution already
    // picks it for the new host, assign it explicitly (hosts.ssh_credential_id; no secret copies).
    const { rows: auto } = await client.query(
      `SELECT ec.cred_id FROM hosts h CROSS JOIN LATERAL (${EFFECTIVE_CREDENTIAL_LATERAL}) ec WHERE h.id = $1`,
      [hostId]
    );
    if (String(auto[0]?.cred_id ?? '') !== String(credRow.id)) {
      await client.query(`UPDATE hosts SET ssh_credential_id = $2 WHERE id = $1`, [hostId, credRow.id]);
    }
    await client.query('COMMIT');
    triggerTemplateAutoApply([params.tagId]);
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }

  void evaluateHostAgainstRules(hostId).catch((e) => {
    // eslint-disable-next-line no-console
    console.error(`[Discovery] Tag rule evaluation for ${hostname} failed:`, e);
  });

  return {
    ip,
    port,
    status: 'imported',
    hostname,
    hostId,
    credentialName: credRow.name,
    osPrettyName: facts.osPrettyName,
    firewallBackend: backend,
    sudo: facts.sudo,
    ...(warnings.length ? { warnings, reason: warnings.join('; ') } : {})
  };
}

// ---------------------------------------------------------------- scheduler

/** Mark RUNNING runs that can no longer be progressing as FAILED. */
export async function failStaleDiscoveryRuns(opts: { all?: boolean } = {}): Promise<number> {
  const { rowCount } = await pool.query(
    `UPDATE discovery_runs
        SET status = 'FAILED', finished_at = now(),
            error = COALESCE(error, $1)
      WHERE status = 'RUNNING' ${opts.all ? '' : `AND started_at < now() - make_interval(hours => ${STALE_RUN_HOURS})`}`,
    [opts.all ? 'interrupted: the API restarted while this run was in progress' : `abandoned: still RUNNING after ${STALE_RUN_HOURS} hours`]
  );
  return rowCount ?? 0;
}

/**
 * Claim due, enabled, scheduled profiles atomically (FOR UPDATE SKIP LOCKED + pushing
 * next_run_at forward in the same statement) and start a run for each.
 */
export async function processScheduledDiscovery(): Promise<number> {
  await failStaleDiscoveryRuns();
  const { rows } = await pool.query(
    `UPDATE discovery_profiles p
        SET next_run_at = now() + make_interval(mins => p.schedule_interval_minutes)
      WHERE p.id IN (
        SELECT id FROM discovery_profiles
         WHERE enabled AND schedule_interval_minutes IS NOT NULL
           AND next_run_at IS NOT NULL AND next_run_at <= now()
         ORDER BY next_run_at
         LIMIT 20
         FOR UPDATE SKIP LOCKED)
      RETURNING p.id, p.name`
  );
  let started = 0;
  for (const p of rows) {
    try {
      await startDiscoveryRun(p.id, 'scheduled', null);
      started++;
    } catch (e) {
      if (!(e instanceof DiscoveryAlreadyRunningError)) throw e;
      // eslint-disable-next-line no-console
      console.log(`[Discovery] Skipping scheduled run of "${p.name}": a run is already in progress`);
    }
  }
  return started;
}
