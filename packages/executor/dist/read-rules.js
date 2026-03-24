import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
/**
 * Read current firewall rules from a host via SSH and compute hash.
 * Normalizes the output for consistent hashing.
 */
export async function readHostFirewallRules(host) {
    if (!host.privateKeyPath) {
        throw new Error('read_rules_requires_private_key');
    }
    const sshOptions = [
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR',
        '-i', host.privateKeyPath,
        '-p', String(host.port),
        `${host.username}@${host.ip}`
    ];
    // Detect backend if auto
    let backend = host.backend === 'iptables' ? 'iptables' : 'nftables';
    if (host.backend === 'auto') {
        const detectCmd = 'command -v nft >/dev/null 2>&1 && echo nft || echo iptables';
        const detectResult = await execSsh(sshOptions, detectCmd);
        backend = detectResult.stdout.trim() === 'nft' ? 'nftables' : 'iptables';
    }
    // Read rules based on backend
    let readCmd;
    if (backend === 'nftables') {
        readCmd = 'sudo -n nft list ruleset 2>&1';
    }
    else {
        readCmd = 'sudo -n iptables-save 2>&1';
    }
    const result = await execSsh(sshOptions, readCmd);
    if (result.exitCode !== 0) {
        return {
            hostname: host.hostname,
            success: false,
            rulesText: '',
            rulesHash: '',
            backend,
            error: result.stderr || 'Failed to read firewall rules'
        };
    }
    const rulesText = normalizeRulesText(result.stdout, backend);
    const rulesHash = crypto.createHash('sha256').update(rulesText, 'utf8').digest('hex');
    return {
        hostname: host.hostname,
        success: true,
        rulesText: result.stdout, // Keep original for display
        rulesHash,
        backend
    };
}
/**
 * Normalize firewall rules text for consistent hashing.
 * Removes timestamps, comments that don't affect functionality, and normalizes whitespace.
 */
function normalizeRulesText(text, backend) {
    let normalized = text;
    if (backend === 'nftables') {
        // Remove comments (but keep segmentra comments for policy matching)
        normalized = normalized.replace(/^\s*#.*$/gm, '');
        // Normalize whitespace
        normalized = normalized.replace(/\s+/g, ' ').trim();
    }
    else {
        // iptables-save format: remove comments except segmentra ones
        normalized = normalized.replace(/^#.*$/gm, '');
        // Normalize whitespace
        normalized = normalized.replace(/\s+/g, ' ').trim();
    }
    return normalized;
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
