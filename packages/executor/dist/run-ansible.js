import { spawn } from 'node:child_process';
import fs from 'node:fs';
export async function runAnsiblePlaybook(params) {
    const args = [
        'exec',
        params.runnerContainer,
        'ansible-playbook',
        '-i',
        params.inventoryPath,
        params.playbookPath
    ];
    const command = `docker ${args.map((a) => (a.includes(' ') ? JSON.stringify(a) : a)).join(' ')}`;
    return await new Promise((resolve) => {
        const child = spawn('docker', args, {
            env: { ...process.env, ...(params.extraEnv ?? {}) },
            stdio: ['ignore', 'pipe', 'pipe']
        });
        if (params.stdoutPath) {
            child.stdout.pipe(fs.createWriteStream(params.stdoutPath));
        }
        if (params.stderrPath) {
            child.stderr.pipe(fs.createWriteStream(params.stderrPath));
        }
        child.on('close', (code) => resolve({ exitCode: code ?? 1, command }));
    });
}
