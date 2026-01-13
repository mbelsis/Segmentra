import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { promisify } from 'node:util';
const writeFile = promisify(fs.writeFile);
const readFile = promisify(fs.readFile);
const unlink = promisify(fs.unlink);
/**
 * Start an audit session: backup rules, deploy log-only policy, configure logging
 */
export async function startAuditSession(host, logFilePath) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    const backupDir = '/var/backups/segmentra';
    const remotePolicyPath = '/tmp/segmentra-audit.policy';
    const backupPath = `${backupDir}/${host.backend === 'nftables' ? 'nft' : 'iptables'}.audit-backup.${timestamp}`;
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
        // Step 2: Backup existing rules
        if (host.backend === 'nftables') {
            const backupCmd = `
        if [ -f /etc/nftables.conf ]; then
          sudo cp /etc/nftables.conf ${backupPath}.conf 2>&1 || true
        fi
        sudo nft list ruleset > ${backupPath} 2>&1 || true
      `;
            const backupResult = await execSsh(sshOptions, backupCmd);
            stdout += backupResult.stdout;
            stderr += backupResult.stderr;
        }
        else {
            const backupCmd = `sudo iptables-save > ${backupPath} 2>&1 || true`;
            const backupResult = await execSsh(sshOptions, backupCmd);
            stdout += backupResult.stdout;
            stderr += backupResult.stderr;
        }
        // Step 3: Configure logging to capture firewall logs
        await configureLogging(host, logFilePath, sshOptions);
        // Step 4: Create log file and set permissions
        const logSetupCmd = `sudo touch ${logFilePath} && sudo chmod 644 ${logFilePath}`;
        const logSetupResult = await execSsh(sshOptions, logSetupCmd);
        stdout += logSetupResult.stdout;
        stderr += logSetupResult.stderr;
        return {
            hostname: host.hostname,
            success: true,
            exitCode: 0,
            stdout,
            stderr,
            backupPath,
            logFilePath
        };
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
/**
 * Configure logging for firewall rules
 */
async function configureLogging(host, logFilePath, sshOptions) {
    if (host.backend === 'nftables') {
        // For nftables, configure rsyslog to capture kernel messages with FW-AUDIT prefix
        // nftables log action writes to kernel log, which rsyslog can capture
        const rsyslogConfig = `/etc/rsyslog.d/99-segmentra-audit.conf`;
        const rsyslogRule = `kern.* :msg, contains, "FW-AUDIT" ${logFilePath}\n& stop\n`;
        const setupCmd = `
      echo '${rsyslogRule}' | sudo tee ${rsyslogConfig} > /dev/null
      sudo systemctl reload rsyslog 2>&1 || sudo service rsyslog reload 2>&1 || sudo killall -HUP rsyslogd 2>&1 || true
    `;
        await execSsh(sshOptions, setupCmd);
    }
    else {
        // For iptables, configure rsyslog to write LOG target messages to custom file
        const rsyslogConfig = `/etc/rsyslog.d/99-segmentra-audit.conf`;
        const rsyslogRule = `kern.* :msg, contains, "FW-AUDIT" ${logFilePath}\n& stop\n`;
        const setupCmd = `
      echo '${rsyslogRule}' | sudo tee ${rsyslogConfig} > /dev/null
      sudo systemctl reload rsyslog 2>&1 || sudo service rsyslog reload 2>&1 || sudo killall -HUP rsyslogd 2>&1 || true
    `;
        await execSsh(sshOptions, setupCmd);
    }
}
/**
 * Deploy log-only firewall policy
 */
export async function deployLogOnlyPolicy(host, policyText, policyFilePath) {
    const remotePolicyPath = '/tmp/segmentra-audit.policy';
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
        // Step 1: Write policy to local temp file
        await writeFile(policyFilePath, policyText, 'utf8');
        await promisify(fs.chmod)(policyFilePath, 0o600);
        // Step 2: Copy policy file to remote host
        const scpOptions = [
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-i', host.privateKeyPath,
            '-P', String(host.port),
            policyFilePath,
            `${host.username}@${host.ip}:${remotePolicyPath}`
        ];
        const scpResult = await execScp(scpOptions);
        stdout += scpResult.stdout;
        stderr += scpResult.stderr;
        if (scpResult.exitCode !== 0) {
            return { hostname: host.hostname, success: false, exitCode: scpResult.exitCode, stdout, stderr };
        }
        // Step 3: Move policy file to secure location and set permissions
        const setupCmd = `sudo mv ${remotePolicyPath} /etc/segmentra-audit.policy && sudo chmod 600 /etc/segmentra-audit.policy`;
        const setupResult = await execSsh(sshOptions, setupCmd);
        stdout += setupResult.stdout;
        stderr += setupResult.stderr;
        if (setupResult.exitCode !== 0) {
            return { hostname: host.hostname, success: false, exitCode: setupResult.exitCode, stdout, stderr };
        }
        // Step 4: Apply firewall rules
        let applyCmd;
        if (host.backend === 'nftables') {
            applyCmd = 'sudo nft -f /etc/segmentra-audit.policy';
        }
        else {
            applyCmd = 'sudo iptables-restore < /etc/segmentra-audit.policy';
        }
        const applyResult = await execSsh(sshOptions, applyCmd);
        stdout += applyResult.stdout;
        stderr += applyResult.stderr;
        if (applyResult.exitCode !== 0) {
            return {
                hostname: host.hostname,
                success: false,
                exitCode: applyResult.exitCode,
                stdout,
                stderr: stderr + '\nFirewall apply failed\n'
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
/**
 * Restore original firewall rules from backup
 */
export async function restoreAuditSession(host, backupPath) {
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
        // Step 1: Remove log-only policy
        if (host.backend === 'nftables') {
            const flushCmd = 'sudo nft flush ruleset 2>&1 || true';
            const flushResult = await execSsh(sshOptions, flushCmd);
            stdout += flushResult.stdout;
            stderr += flushResult.stderr;
        }
        else {
            const flushCmd = 'sudo iptables -F INPUT && sudo iptables -F OUTPUT && sudo iptables -F FORWARD 2>&1 || true';
            const flushResult = await execSsh(sshOptions, flushCmd);
            stdout += flushResult.stdout;
            stderr += flushResult.stderr;
        }
        // Step 2: Restore from backup
        if (host.backend === 'nftables') {
            const restoreCmd = `sudo nft -f ${backupPath} 2>&1 || true`;
            const restoreResult = await execSsh(sshOptions, restoreCmd);
            stdout += restoreResult.stdout;
            stderr += restoreResult.stderr;
            exitCode = restoreResult.exitCode;
        }
        else {
            const restoreCmd = `sudo iptables-restore < ${backupPath} 2>&1 || true`;
            const restoreResult = await execSsh(sshOptions, restoreCmd);
            stdout += restoreResult.stdout;
            stderr += restoreResult.stderr;
            exitCode = restoreResult.exitCode;
        }
        // Step 3: Clean up audit policy file and rsyslog config
        const cleanupCmd = `
      sudo rm -f /etc/segmentra-audit.policy 2>&1 || true
      sudo rm -f /etc/rsyslog.d/99-segmentra-audit.conf 2>&1 || true
      sudo systemctl reload rsyslog 2>&1 || sudo service rsyslog reload 2>&1 || sudo killall -HUP rsyslogd 2>&1 || true
    `;
        const cleanupResult = await execSsh(sshOptions, cleanupCmd);
        stdout += cleanupResult.stdout;
        stderr += cleanupResult.stderr;
        return {
            hostname: host.hostname,
            success: exitCode === 0,
            exitCode,
            stdout,
            stderr
        };
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
/**
 * Retrieve audit log file from remote server
 */
export async function retrieveAuditLogs(host, remoteLogPath, localLogPath) {
    const scpOptions = [
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR',
        '-i', host.privateKeyPath,
        '-P', String(host.port),
        `${host.username}@${host.ip}:${remoteLogPath}`,
        localLogPath
    ];
    let stdout = '';
    let stderr = '';
    let exitCode = 0;
    try {
        const scpResult = await execScp(scpOptions);
        stdout += scpResult.stdout;
        stderr += scpResult.stderr;
        exitCode = scpResult.exitCode;
        // Read the file to verify it was copied
        if (exitCode === 0 && fs.existsSync(localLogPath)) {
            const content = await readFile(localLogPath, 'utf8');
            stdout += `\nRetrieved ${content.length} bytes from ${remoteLogPath}\n`;
        }
        return {
            hostname: host.hostname,
            success: exitCode === 0,
            exitCode,
            stdout,
            stderr
        };
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
