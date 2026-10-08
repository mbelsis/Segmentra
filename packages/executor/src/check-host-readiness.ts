import type { SshHostInfo } from './types.js';
import { runSshCommand, runSshSudo, usesSudoPassword, type SshConnectionOptions, type SudoErrorKind } from './ssh-options.js';

export interface HostReadinessResult {
  hostname: string;
  ready: boolean;
  backend: 'nftables' | 'iptables' | 'unknown';
  nftVersion?: string;
  iptablesVersion?: string;
  sudoAccess: boolean;
  /** How sudo was tested: 'nopasswd' (sudo -n) or 'password' (sudo -k -S with the configured password). */
  sudoMode: 'nopasswd' | 'password';
  /** Why the sudo test failed, when sudoAccess is false and sudo itself refused. */
  sudoError?: SudoErrorKind;
  kernelSupport: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Check if a host is ready for firewall deployments.
 * Verifies:
 * - SSH connectivity (key or password auth)
 * - Presence and versions of nft/iptables
 * - sudo access with the configured method: passwordless (`sudo -n`) or with the
 *   configured sudo password (`sudo -k -S`, password on stdin); Segmentra runs `sh` as root
 * - Kernel/module support for nftables (if applicable)
 */
export async function checkHostReadiness(host: SshHostInfo, opts: SshConnectionOptions = {}): Promise<HostReadinessResult> {
  const authMethod = host.authMethod ?? (host.privateKeyPath ? 'key' : host.password ? 'password' : 'key');
  if (authMethod === 'key' && !host.privateKeyPath) {
    throw new Error('check_host_readiness_requires_private_key');
  }
  if (authMethod === 'password' && !host.password) {
    throw new Error('check_host_readiness_requires_password');
  }

  const run = (cmd: string) => runSshCommand(host, cmd, opts);

  const result: HostReadinessResult = {
    hostname: host.hostname,
    ready: true,
    backend: 'unknown',
    sudoAccess: false,
    sudoMode: usesSudoPassword(host) ? 'password' : 'nopasswd',
    kernelSupport: false,
    errors: [],
    warnings: []
  };

  // Connectivity check first so SSH failures aren't misreported as missing tools
  const ping = await run('echo segmentra-ok');
  if (ping.exitCode !== 0 || !ping.stdout.includes('segmentra-ok')) {
    result.ready = false;
    const detail = (ping.stderr || ping.stdout).trim() || `exit code ${ping.exitCode}`;
    const hint =
      host.keyPassphrase && /Permission denied/i.test(detail)
        ? ' (the key was rejected or its passphrase is wrong; check the credential\'s key passphrase)'
        : '';
    result.errors.push(`SSH connection failed: ${detail}${hint}`);
    return result;
  }

  const nftCheck = await run('command -v nft 2>/dev/null');
  const hasNft = nftCheck.exitCode === 0 && nftCheck.stdout.trim() !== '';

  const iptablesCheck = await run('command -v iptables 2>/dev/null');
  const hasIptables = iptablesCheck.exitCode === 0 && iptablesCheck.stdout.trim() !== '';

  if (!hasNft && !hasIptables) {
    result.ready = false;
    result.errors.push('Neither nftables nor iptables is available');
    return result;
  }

  // Honour the host's configured backend when its tool exists; otherwise prefer nftables.
  const useIptables = host.backend === 'iptables' ? hasIptables : !hasNft;
  if (host.backend === 'iptables' && !hasIptables) {
    result.ready = false;
    result.errors.push('Host is configured for iptables, but iptables is not installed');
  } else if (host.backend === 'nftables' && !hasNft) {
    result.ready = false;
    result.errors.push('Host is configured for nftables, but nft is not installed');
  }
  if (!useIptables) {
    result.backend = 'nftables';
    const nftVersion = await run('nft --version 2>&1');
    if (nftVersion.exitCode === 0) result.nftVersion = nftVersion.stdout.trim();
  } else {
    result.backend = 'iptables';
    const iptablesVersion = await run('iptables --version 2>&1');
    if (iptablesVersion.exitCode === 0) result.iptablesVersion = iptablesVersion.stdout.trim();
  }

  // Check sudo with the configured method. Deployments run every root step as `sudo sh -c`,
  // so test exactly that (and that the shell really runs as root), plus read the ruleset.
  const readCmd = useIptables ? 'iptables-save >/dev/null' : 'nft list ruleset >/dev/null';
  const sudoTest = await runSshSudo(host, `id -u; ${readCmd}`, opts);
  const uid = sudoTest.stdout.trim().split('\n')[0]?.trim();
  if (sudoTest.exitCode === 0 && uid === '0') {
    result.sudoAccess = true;
  } else {
    result.ready = false;
    if (sudoTest.sudoError) {
      result.sudoError = sudoTest.sudoError;
      result.errors.push((sudoTest.stderr.trim().split('\n').pop() ?? '').replace(/^Error:\s*/, ''));
    } else if (uid === '0') {
      const detail = (sudoTest.stderr || sudoTest.stdout).trim().split('\n').pop() ?? '';
      result.sudoAccess = true;
      result.errors.push(`Reading the firewall ruleset as root failed${detail ? `: ${detail}` : ''}`);
    } else {
      const detail = (sudoTest.stderr || sudoTest.stdout).trim().split('\n').pop() || `exit code ${sudoTest.exitCode}`;
      result.errors.push(
        `${usesSudoPassword(host) ? 'sudo with the configured password' : 'Passwordless sudo'} failed: ${detail}`
      );
    }
  }

  if (hasNft) {
    const kernelCheck = await run('lsmod 2>/dev/null | grep -q nf_tables && echo yes || echo no');
    if (kernelCheck.stdout.trim() === 'yes') {
      result.kernelSupport = true;
    } else {
      result.warnings.push('nf_tables kernel module not loaded (may still work)');
    }
  }

  if (hasIptables && !hasNft) {
    const restoreCheck = await run('command -v iptables-restore 2>/dev/null');
    if (restoreCheck.exitCode !== 0) {
      result.ready = false;
      result.errors.push('iptables-restore is not available');
    }
    const restore6Check = await run('command -v ip6tables-restore 2>/dev/null');
    if (restore6Check.exitCode !== 0) {
      result.warnings.push('ip6tables-restore is not available; IPv6 rules will not be applied');
    }
  }

  // Lockout protection uses systemd-run or nohup to schedule an automatic revert
  const schedCheck = await run('command -v systemd-run >/dev/null 2>&1 || command -v nohup >/dev/null 2>&1');
  if (schedCheck.exitCode !== 0) {
    result.warnings.push('Neither systemd-run nor nohup found; automatic revert (lockout protection) may not work');
  }

  return result;
}
