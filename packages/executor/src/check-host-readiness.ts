import type { SshHostInfo } from './types.js';
import { runSshCommand, type SshConnectionOptions } from './ssh-options.js';

export interface HostReadinessResult {
  hostname: string;
  ready: boolean;
  backend: 'nftables' | 'iptables' | 'unknown';
  nftVersion?: string;
  iptablesVersion?: string;
  sudoAccess: boolean;
  kernelSupport: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Check if a host is ready for firewall deployments.
 * Verifies:
 * - SSH connectivity (key or password auth)
 * - Presence and versions of nft/iptables
 * - Passwordless sudo access for firewall commands
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
    kernelSupport: false,
    errors: [],
    warnings: []
  };

  // Connectivity check first so SSH failures aren't misreported as missing tools
  const ping = await run('echo segmentra-ok');
  if (ping.exitCode !== 0 || !ping.stdout.includes('segmentra-ok')) {
    result.ready = false;
    result.errors.push(`SSH connection failed: ${(ping.stderr || ping.stdout).trim() || `exit code ${ping.exitCode}`}`);
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

  // Determine backend preference (nftables preferred)
  if (hasNft) {
    result.backend = 'nftables';
    const nftVersion = await run('nft --version 2>&1');
    if (nftVersion.exitCode === 0) result.nftVersion = nftVersion.stdout.trim();
  } else {
    result.backend = 'iptables';
    const iptablesVersion = await run('iptables --version 2>&1');
    if (iptablesVersion.exitCode === 0) result.iptablesVersion = iptablesVersion.stdout.trim();
  }

  // Check passwordless sudo for firewall commands
  const sudoTests: string[] = [];
  if (hasNft) sudoTests.push('sudo -n nft list ruleset 2>&1');
  if (hasIptables) sudoTests.push('sudo -n iptables-save 2>&1');

  let sudoPassed = false;
  for (const testCmd of sudoTests) {
    const sudoTest = await run(testCmd);
    const output = `${sudoTest.stdout}\n${sudoTest.stderr}`.toLowerCase();
    // Exit code 0 = success; otherwise sudo worked only if it didn't ask for a password
    if (sudoTest.exitCode === 0 || (sudoTest.exitCode !== 1 && !output.includes('password'))) {
      sudoPassed = true;
      break;
    }
  }

  if (!sudoPassed) {
    result.ready = false;
    result.errors.push('Passwordless sudo access required for firewall commands (nft/iptables)');
  } else {
    result.sudoAccess = true;
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
