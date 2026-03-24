import { spawn } from 'node:child_process';
/**
 * Check if a host is ready for firewall deployments.
 * Verifies:
 * - Presence and versions of nft/iptables
 * - Passwordless sudo access for firewall commands
 * - Kernel/module support for nftables (if applicable)
 */
export async function checkHostReadiness(host) {
    if (!host.privateKeyPath) {
        throw new Error('check_host_readiness_requires_private_key');
    }
    const sshOptions = [
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR',
        '-i', host.privateKeyPath,
        '-p', String(host.port),
        `${host.username}@${host.ip}`
    ];
    const result = {
        hostname: host.hostname,
        ready: true,
        backend: 'unknown',
        sudoAccess: false,
        kernelSupport: false,
        errors: [],
        warnings: []
    };
    // Check for nft
    const nftCheck = await execSsh(sshOptions, 'command -v nft 2>/dev/null');
    const hasNft = nftCheck.exitCode === 0 && nftCheck.stdout.trim() !== '';
    // Check for iptables
    const iptablesCheck = await execSsh(sshOptions, 'command -v iptables 2>/dev/null');
    const hasIptables = iptablesCheck.exitCode === 0 && iptablesCheck.stdout.trim() !== '';
    if (!hasNft && !hasIptables) {
        result.ready = false;
        result.errors.push('Neither nftables nor iptables is available');
        return result;
    }
    // Determine backend preference (nftables preferred)
    if (hasNft) {
        result.backend = 'nftables';
        const nftVersion = await execSsh(sshOptions, 'nft --version 2>&1');
        if (nftVersion.exitCode === 0) {
            result.nftVersion = nftVersion.stdout.trim();
        }
    }
    else {
        result.backend = 'iptables';
        const iptablesVersion = await execSsh(sshOptions, 'iptables --version 2>&1');
        if (iptablesVersion.exitCode === 0) {
            result.iptablesVersion = iptablesVersion.stdout.trim();
        }
    }
    // Check passwordless sudo for firewall commands
    const sudoTests = [];
    if (hasNft) {
        sudoTests.push('sudo -n nft list ruleset 2>&1');
    }
    if (hasIptables) {
        sudoTests.push('sudo -n iptables-save 2>&1');
    }
    let sudoPassed = false;
    for (const testCmd of sudoTests) {
        const sudoTest = await execSsh(sshOptions, testCmd);
        // Exit code 0 = success, 1 = auth failure, other = command error (but sudo worked)
        if (sudoTest.exitCode === 0 || (sudoTest.exitCode !== 1 && !sudoTest.stderr.includes('password'))) {
            sudoPassed = true;
            break;
        }
    }
    if (!sudoPassed) {
        result.ready = false;
        result.errors.push('Passwordless sudo access required for firewall commands (nft/iptables)');
    }
    else {
        result.sudoAccess = true;
    }
    // Check kernel support for nftables (if nft is available)
    if (hasNft) {
        const kernelCheck = await execSsh(sshOptions, 'lsmod | grep -q nf_tables && echo yes || echo no');
        if (kernelCheck.stdout.trim() === 'yes') {
            result.kernelSupport = true;
        }
        else {
            result.warnings.push('nf_tables kernel module not loaded (may still work)');
        }
    }
    // Check iptables-restore availability (needed for iptables backend)
    if (hasIptables && !hasNft) {
        const restoreCheck = await execSsh(sshOptions, 'command -v iptables-restore 2>/dev/null');
        if (restoreCheck.exitCode !== 0) {
            result.ready = false;
            result.errors.push('iptables-restore is not available');
        }
    }
    return result;
}
function execSsh(sshOptions, command) {
    return new Promise((resolve) => {
        const args = [...sshOptions, command];
        const child = spawn('ssh', args);
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (data) => {
            stdout += data.toString();
        });
        child.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        child.on('close', (code) => {
            resolve({ exitCode: code ?? 1, stdout, stderr });
        });
        child.on('error', (error) => {
            resolve({ exitCode: 1, stdout, stderr: stderr + error.message });
        });
    });
}
