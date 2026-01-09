import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { promisify } from 'node:util';
const writeFile = promisify(fs.writeFile);
const chmod = promisify(fs.chmod);
/**
 * Execute SSH commands directly on a host to apply firewall rules.
 * Uses sudo for all privileged operations.
 */
export async function runSshDeployment(params) {
    const results = [];
    const allStdout = [];
    const allStderr = [];
    for (const host of params.hosts) {
        const result = await deployToHost(host);
        results.push(result);
        allStdout.push(`=== ${host.hostname} ===\n${result.stdout}\n`);
        allStderr.push(`=== ${host.hostname} ===\n${result.stderr}\n`);
    }
    // Write combined logs if paths provided
    if (params.stdoutPath) {
        await writeFile(params.stdoutPath, allStdout.join('\n'), 'utf8');
    }
    if (params.stderrPath) {
        await writeFile(params.stderrPath, allStderr.join('\n'), 'utf8');
    }
    return results;
}
async function deployToHost(host) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    const backupDir = '/var/backups/segmentra';
    const remotePolicyPath = '/tmp/segmentra.policy';
    const ext = host.backend === 'nftables' ? 'nft' : 'iptables';
    // SSH options
    const sshOptions = [
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR',
        '-i', host.privateKeyPath,
        '-p', String(host.port),
        `${host.username}@${host.ip}`
    ];
    let stdout = '';
    let stderr = '';
    let exitCode = 0;
    try {
        // Step 1: Ensure backup directory exists
        const mkdirCmd = `sudo mkdir -p ${backupDir} && sudo chmod 700 ${backupDir}`;
        const mkdirResult = await execSsh(sshOptions, mkdirCmd);
        stdout += mkdirResult.stdout;
        stderr += mkdirResult.stderr;
        if (mkdirResult.exitCode !== 0) {
            return { hostname: host.hostname, success: false, exitCode: mkdirResult.exitCode, stdout, stderr };
        }
        // Step 2: Detect backend
        const detectCmd = 'command -v nft >/dev/null 2>&1 && echo nft || echo iptables';
        const detectResult = await execSsh(sshOptions, detectCmd);
        const detectedBackend = detectResult.stdout.trim();
        stdout += `Detected backend: ${detectedBackend}\n`;
        // Step 3: Backup existing rules
        if (detectedBackend === 'nft') {
            const backupCmd = `
        if [ -f /etc/nftables.conf ]; then
          sudo cp /etc/nftables.conf ${backupDir}/nftables.conf.${timestamp}
        fi
        sudo nft list ruleset > ${backupDir}/nft.ruleset.${timestamp} 2>&1 || true
      `;
            const backupResult = await execSsh(sshOptions, backupCmd);
            stdout += backupResult.stdout;
            stderr += backupResult.stderr;
        }
        else {
            const backupCmd = `sudo iptables-save > ${backupDir}/iptables.${timestamp} 2>&1 || true`;
            const backupResult = await execSsh(sshOptions, backupCmd);
            stdout += backupResult.stdout;
            stderr += backupResult.stderr;
        }
        // Step 4: Copy policy file to remote host
        const scpOptions = [
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-i', host.privateKeyPath,
            '-P', String(host.port),
            host.policyFilePath,
            `${host.username}@${host.ip}:${remotePolicyPath}`
        ];
        const scpResult = await execScp(scpOptions);
        stdout += scpResult.stdout;
        stderr += scpResult.stderr;
        if (scpResult.exitCode !== 0) {
            return { hostname: host.hostname, success: false, exitCode: scpResult.exitCode, stdout, stderr };
        }
        // Step 5: Move policy file to secure location and set permissions
        const setupCmd = `sudo mv ${remotePolicyPath} /etc/segmentra.policy && sudo chmod 600 /etc/segmentra.policy`;
        const setupResult = await execSsh(sshOptions, setupCmd);
        stdout += setupResult.stdout;
        stderr += setupResult.stderr;
        if (setupResult.exitCode !== 0) {
            return { hostname: host.hostname, success: false, exitCode: setupResult.exitCode, stdout, stderr };
        }
        // Step 6: Apply firewall rules
        let applyCmd;
        if (detectedBackend === 'nft' && ext === 'nft') {
            applyCmd = 'sudo nft -f /etc/segmentra.policy';
        }
        else if (detectedBackend !== 'nft' && ext === 'iptables') {
            applyCmd = 'sudo iptables-restore < /etc/segmentra.policy';
        }
        else {
            return {
                hostname: host.hostname,
                success: false,
                exitCode: 1,
                stdout,
                stderr: stderr + `\nError: Backend mismatch. Detected: ${detectedBackend}, Policy: ${ext}\n`
            };
        }
        const applyResult = await execSsh(sshOptions, applyCmd);
        stdout += applyResult.stdout;
        stderr += applyResult.stderr;
        if (applyResult.exitCode !== 0) {
            // Rollback on failure
            stdout += '\n=== Rollback attempt ===\n';
            if (detectedBackend === 'nft') {
                const rollbackCmd = `
          latest=$(ls -1t ${backupDir}/nft.ruleset.* 2>/dev/null | head -n 1)
          if [ -n "$latest" ]; then
            sudo nft -f "$latest" 2>&1 || true
          fi
        `;
                const rollbackResult = await execSsh(sshOptions, rollbackCmd);
                stdout += rollbackResult.stdout;
                stderr += rollbackResult.stderr;
            }
            else {
                const rollbackCmd = `
          latest=$(ls -1t ${backupDir}/iptables.* 2>/dev/null | head -n 1)
          if [ -n "$latest" ]; then
            sudo iptables-restore < "$latest" 2>&1 || true
          fi
        `;
                const rollbackResult = await execSsh(sshOptions, rollbackCmd);
                stdout += rollbackResult.stdout;
                stderr += rollbackResult.stderr;
            }
            return {
                hostname: host.hostname,
                success: false,
                exitCode: applyResult.exitCode,
                stdout,
                stderr: stderr + '\nFirewall apply failed; rollback attempted\n'
            };
        }
        return { hostname: host.hostname, success: true, exitCode: 0, stdout, stderr };
    }
    catch (error) {
        return {
            hostname: host.hostname,
            success: false,
            exitCode: 1,
            stdout,
            stderr: stderr + `\nException: ${error.message}\n`
        };
    }
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
function execScp(scpOptions) {
    return new Promise((resolve) => {
        const child = spawn('scp', scpOptions);
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
