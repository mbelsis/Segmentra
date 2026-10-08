import { spawn } from 'node:child_process';
import fs from 'node:fs';

export const DEFAULT_ANSIBLE_TIMEOUT_MS = 30 * 60 * 1000;

export async function runAnsiblePlaybook(params: {
  runnerContainer: string;
  inventoryPath: string; // path inside runner container
  playbookPath: string; // path inside runner container
  extraEnv?: Record<string, string>;
  stdoutPath?: string; // host filesystem path
  stderrPath?: string; // host filesystem path
  /** Overall timeout in ms (default 30 minutes). The playbook is killed when exceeded. */
  timeoutMs?: number;
}): Promise<{ exitCode: number; command: string; timedOut?: boolean; error?: string }> {
  const timeoutMs = params.timeoutMs && params.timeoutMs > 0 ? params.timeoutMs : DEFAULT_ANSIBLE_TIMEOUT_MS;
  const timeoutSec = Math.ceil(timeoutMs / 1000);
  const ansibleArgs = ['ansible-playbook', '-i', params.inventoryPath, params.playbookPath];
  // `timeout` runs inside the container so the playbook itself is killed, not just the docker client.
  const args = ['exec', params.runnerContainer, 'timeout', '--kill-after=30', String(timeoutSec), ...ansibleArgs];

  const command = `docker ${['exec', params.runnerContainer, ...ansibleArgs]
    .map((a) => (a.includes(' ') ? JSON.stringify(a) : a))
    .join(' ')}`;

  return await new Promise((resolve) => {
    let settled = false;
    let timedOut = false;
    let killTimer: NodeJS.Timeout | undefined;
    const finish = (r: { exitCode: number; command: string; timedOut?: boolean; error?: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      resolve(r);
    };

    const child = spawn('docker', args, {
      env: { ...process.env, ...(params.extraEnv ?? {}) },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    // Local backstop in case the in-container timeout doesn't fire (docker hang etc.)
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      killTimer = setTimeout(() => child.kill('SIGKILL'), 10_000);
    }, timeoutMs + 60_000);

    const onStreamError = () => { /* ignore log stream errors; exit code still reported */ };
    if (params.stdoutPath) {
      const ws = fs.createWriteStream(params.stdoutPath);
      ws.on('error', onStreamError);
      child.stdout.pipe(ws);
    } else {
      child.stdout.resume();
    }
    if (params.stderrPath) {
      const ws = fs.createWriteStream(params.stderrPath);
      ws.on('error', onStreamError);
      child.stderr.pipe(ws);
    } else {
      child.stderr.resume();
    }

    child.on('error', (err) => finish({ exitCode: 1, command, error: err.message }));
    child.on('close', (code) => {
      // coreutils timeout exits 124 when the time limit is hit
      const inContainerTimeout = code === 124;
      if (timedOut || inContainerTimeout) {
        finish({ exitCode: code && code !== 0 ? code : 124, command, timedOut: true, error: `ansible-playbook timed out after ${timeoutMs}ms` });
      } else {
        finish({ exitCode: code ?? 1, command });
      }
    });
  });
}
