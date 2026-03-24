import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { promisify } from 'node:util';
const writeFile = promisify(fs.writeFile);
/**
 * Build SSH options array. Uses a known_hosts file if provided,
 * otherwise falls back to StrictHostKeyChecking=no.
 */
function buildSshOptions(host, knownHostsPath) {
    const opts = [];
    if (knownHostsPath && fs.existsSync(knownHostsPath)) {
        opts.push('-o', `UserKnownHostsFile=${knownHostsPath}`);
        opts.push('-o', 'StrictHostKeyChecking=yes');
    }
    else {
        opts.push('-o', 'StrictHostKeyChecking=no');
        opts.push('-o', 'UserKnownHostsFile=/dev/null');
    }
    opts.push('-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=30');
    if ((host.authMethod ?? 'key') === 'key') {
        if (!host.privateKeyPath)
            throw new Error(`Missing privateKeyPath for host ${host.hostname ?? host.ip}`);
        opts.push('-i', host.privateKeyPath);
    }
    else {
        opts.push('-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password,keyboard-interactive');
    }
    opts.push('-p', String(host.port), `${host.username}@${host.ip}`);
    return opts;
}
function buildScpOptions(host, knownHostsPath) {
    const opts = [];
    if (knownHostsPath && fs.existsSync(knownHostsPath)) {
        opts.push('-o', `UserKnownHostsFile=${knownHostsPath}`);
        opts.push('-o', 'StrictHostKeyChecking=yes');
    }
    else {
        opts.push('-o', 'StrictHostKeyChecking=no');
        opts.push('-o', 'UserKnownHostsFile=/dev/null');
    }
    opts.push('-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=30');
    if ((host.authMethod ?? 'key') === 'key') {
        if (!host.privateKeyPath)
            throw new Error(`Missing privateKeyPath for host ${host.hostname ?? host.ip}`);
        opts.push('-i', host.privateKeyPath);
    }
    else {
        opts.push('-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password,keyboard-interactive');
    }
    opts.push('-P', String(host.port));
    return opts;
}
/**
 * Execute SSH deployment to multiple hosts.
 *
 * @param shouldContinue - Optional callback checked between hosts. Return false to stop.
 *                         This allows the deployment to be cancelled/stopped mid-execution.
 * @param knownHostsPath - Optional path to a known_hosts file for SSH host key verification.
 */
export async function runSshDeployment(params) {
    const results = [];
    const allStdout = [];
    const allStderr = [];
    for (const host of params.hosts) {
        // Check if we should continue before each host
        if (params.shouldContinue) {
            const cont = await params.shouldContinue();
            if (!cont) {
                // Mark remaining hosts as skipped
                results.push({
                    hostname: host.hostname,
                    success: false,
                    exitCode: 0,
                    stdout: 'Skipped: deployment was stopped before this host was processed',
                    stderr: '',
                    skipped: true,
                });
                allStdout.push(`=== ${host.hostname} ===\nSkipped (deployment stopped)\n`);
                continue;
            }
        }
        const result = await deployToHost(host, params.knownHostsPath);
        results.push(result);
        allStdout.push(`=== ${host.hostname} ===\n${result.stdout}\n`);
        allStderr.push(`=== ${host.hostname} ===\n${result.stderr}\n`);
    }
    if (params.stdoutPath) {
        await writeFile(params.stdoutPath, allStdout.join('\n'), 'utf8');
    }
    if (params.stderrPath) {
        await writeFile(params.stderrPath, allStderr.join('\n'), 'utf8');
    }
    return results;
}
async function deployToHost(host, knownHostsPath) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    const backupDir = '/var/backups/segmentra';
    const remotePolicyPath = '/tmp/segmentra.policy';
    const ext = host.backend === 'nftables' ? 'nft' : 'iptables';
    const sshOptions = buildSshOptions(host, knownHostsPath);
    let stdout = '';
    let stderr = '';
    try {
        // Step 1: Ensure backup directory exists
        const mkdirCmd = `sudo mkdir -p ${backupDir} && sudo chmod 700 ${backupDir}`;
        const mkdirResult = await execSsh(sshOptions, mkdirCmd, host.password);
        stdout += mkdirResult.stdout;
        stderr += mkdirResult.stderr;
        if (mkdirResult.exitCode !== 0) {
            return { hostname: host.hostname, success: false, exitCode: mkdirResult.exitCode, stdout, stderr };
        }
        // Step 2: Detect backend
        const detectCmd = 'command -v nft >/dev/null 2>&1 && echo nft || echo iptables';
        const detectResult = await execSsh(sshOptions, detectCmd, host.password);
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
            const backupResult = await execSsh(sshOptions, backupCmd, host.password);
            stdout += backupResult.stdout;
            stderr += backupResult.stderr;
        }
        else {
            const backupCmd = `sudo iptables-save > ${backupDir}/iptables.${timestamp} 2>&1 || true`;
            const backupResult = await execSsh(sshOptions, backupCmd, host.password);
            stdout += backupResult.stdout;
            stderr += backupResult.stderr;
        }
        // Step 4: Copy policy file to remote host
        const scpOpts = buildScpOptions(host, knownHostsPath);
        scpOpts.push(host.policyFilePath, `${host.username}@${host.ip}:${remotePolicyPath}`);
        const scpResult = await execScp(scpOpts, host.password);
        stdout += scpResult.stdout;
        stderr += scpResult.stderr;
        if (scpResult.exitCode !== 0) {
            return { hostname: host.hostname, success: false, exitCode: scpResult.exitCode, stdout, stderr };
        }
        // Step 5: Move policy file to secure location
        const setupCmd = `sudo mv ${remotePolicyPath} /etc/segmentra.policy && sudo chmod 600 /etc/segmentra.policy`;
        const setupResult = await execSsh(sshOptions, setupCmd, host.password);
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
        const applyResult = await execSsh(sshOptions, applyCmd, host.password);
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
                const rollbackResult = await execSsh(sshOptions, rollbackCmd, host.password);
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
                const rollbackResult = await execSsh(sshOptions, rollbackCmd, host.password);
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
function execSsh(sshOptions, command, password) {
    return new Promise((resolve) => {
        const args = password ? ['-p', password, 'ssh', ...sshOptions, command] : [...sshOptions, command];
        const child = spawn(password ? 'sshpass' : 'ssh', args);
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (data) => { stdout += data.toString(); });
        child.stderr.on('data', (data) => { stderr += data.toString(); });
        child.on('close', (code) => { resolve({ exitCode: code ?? 1, stdout, stderr }); });
        child.on('error', (error) => { resolve({ exitCode: 1, stdout, stderr: stderr + error.message }); });
    });
}
function execScp(scpOptions, password) {
    return new Promise((resolve) => {
        const args = password ? ['-p', password, 'scp', ...scpOptions] : scpOptions;
        const child = spawn(password ? 'sshpass' : 'scp', args);
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (data) => { stdout += data.toString(); });
        child.stderr.on('data', (data) => { stderr += data.toString(); });
        child.on('close', (code) => { resolve({ exitCode: code ?? 1, stdout, stderr }); });
        child.on('error', (error) => { resolve({ exitCode: 1, stdout, stderr: stderr + error.message }); });
    });
}
