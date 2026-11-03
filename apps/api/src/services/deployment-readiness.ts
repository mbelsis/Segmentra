import { checkHostReadiness, type SshHostInfo } from '@segmentra/executor';
import { pool } from '../db/pool.js';
import { getSshCredentialForHost, sshAuthFields, type MaterializedSshCredential } from './ssh-credentials.js';

/** Hosts checked at the same time, and how long one host may take, so one dead host cannot hold up a start. */
const CONCURRENCY = 25;
const HOST_TIMEOUT_MS = 60_000;

export interface HostReadinessIssue {
  hostname: string;
  messages: string[];
}

export interface DeploymentReadiness {
  checked: number;
  /** Hosts that cannot be deployed to. */
  blocked: HostReadinessIssue[];
  /** Hosts that can be deployed to, but somebody has to accept what is noted (rules lost on reboot). */
  notes: HostReadinessIssue[];
}

interface HostRow {
  id: string;
  hostname: string;
  mgmt_ip: unknown;
  ssh_port: number | null;
  firewall_backend: string | null;
}

async function checkOne(host: HostRow): Promise<{ blocked?: string[]; notes?: string[] }> {
  if (!host.mgmt_ip) return { blocked: ['The host has no management IP.'] };
  let cred: MaterializedSshCredential;
  try {
    cred = await getSshCredentialForHost(host.id);
  } catch (e: any) {
    if (e?.message === 'missing_ssh_credential') return { blocked: ['No SSH credential applies to this host.'] };
    throw e;
  }
  let timer: NodeJS.Timeout | undefined;
  try {
    const info: SshHostInfo = {
      hostname: host.hostname,
      ip: String(host.mgmt_ip).split('/')[0],
      port: Number(host.ssh_port) || 22,
      ...sshAuthFields(cred),
      backend: ['iptables', 'nftables', 'firewalld', 'ufw'].includes(host.firewall_backend ?? '') ? (host.firewall_backend as SshHostInfo['backend']) : 'auto'
    };
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`The readiness check did not finish within ${HOST_TIMEOUT_MS / 1000} seconds.`)), HOST_TIMEOUT_MS);
    });
    const result = await Promise.race([checkHostReadiness(info, { timeoutMs: HOST_TIMEOUT_MS }), timeout]);
    if (!result.ready) return { blocked: result.errors.length ? result.errors : ['The host is not ready for deployments.'] };
    return result.persistence?.available === false
      ? { notes: result.warnings.filter((w) => w.startsWith('Rules will not survive a reboot')) }
      : {};
  } catch (e: any) {
    return { blocked: [e?.message ?? String(e)] };
  } finally {
    if (timer) clearTimeout(timer);
    cred.cleanup();
  }
}

/**
 * The readiness check is compulsory before a host's first policy: it runs for this deployment's hosts that are about
 * to be deployed and have never had a successful deployment. Hosts already managed by Segmentra are not checked again.
 */
export async function checkFirstDeploymentReadiness(deploymentId: string): Promise<DeploymentReadiness> {
  const { rows } = await pool.query<HostRow>(
    `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM deployment_hosts dh
     JOIN hosts h ON h.id = dh.host_id
     WHERE dh.deployment_id = $1 AND dh.status = 'PENDING'
       AND NOT EXISTS (SELECT 1 FROM deployment_hosts done WHERE done.host_id = h.id AND done.status = 'SUCCEEDED')
     ORDER BY h.hostname`,
    [deploymentId]
  );

  const outcome: DeploymentReadiness = { checked: rows.length, blocked: [], notes: [] };
  for (let i = 0; i < rows.length; i += CONCURRENCY) {
    const batch = rows.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(checkOne));
    results.forEach((r, n) => {
      const hostname = batch[n].hostname;
      if (r.blocked) outcome.blocked.push({ hostname, messages: r.blocked });
      else if (r.notes?.length) outcome.notes.push({ hostname, messages: r.notes });
    });
  }
  return outcome;
}
