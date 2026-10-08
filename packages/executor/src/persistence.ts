/**
 * Reboot persistence helpers that talk to a host (see persist-scripts.ts for the design).
 */
import type { SshHostInfo } from './types.js';
import { runSshSudo, type SshConnectionOptions } from './ssh-options.js';
import { persistSnippet } from './firewall-backup.js';
import { parsePersistenceOutput, type PersistenceResult } from './persist-scripts.js';

/**
 * Report (without changing anything) whether Segmentra's live state is persisted with the
 * distribution's own service, which method would be used and what prevents it (firewalld,
 * missing package, unsupported distro). Uses the inline host script, so it works on hosts
 * Segmentra never deployed to (readiness) and after Ansible runs.
 */
export async function checkHostPersistence(
  host: SshHostInfo,
  backend: 'nftables' | 'iptables',
  opts: SshConnectionOptions = {}
): Promise<PersistenceResult & { error?: string }> {
  try {
    const r = await runSshSudo(host, persistSnippet(backend, 'check'), opts);
    const parsed = parsePersistenceOutput(r.stdout);
    if (parsed.status === 'unknown') {
      return { ...parsed, error: (r.stderr || r.stdout || `exit code ${r.exitCode}`).trim().split('\n').pop() };
    }
    return parsed;
  } catch (e: any) {
    return { status: 'unknown', method: null, distro: null, state: null, warnings: [], notes: [], families: [], error: e?.message ?? String(e) };
  }
}

/** Warning codes that mean the method itself is unavailable (not just "not enabled yet"). */
export const PERSISTENCE_BLOCKING_CODES = [
  'unsupported_distro',
  'no_nftables_service',
  'firewalld_active',
  'iptables_persistent_missing',
  'iptables_services_missing'
];

/** True when the host can persist rules with its distribution's service (readiness view). */
export function persistenceAvailable(p: PersistenceResult): boolean {
  if (p.status === 'unknown') return false;
  return !p.warnings.some((w) => PERSISTENCE_BLOCKING_CODES.includes(w.split(':')[0]));
}
