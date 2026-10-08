import { spawn } from 'node:child_process';
import fs from 'node:fs';

export const DEFAULT_ANSIBLE_TIMEOUT_MS = 30 * 60 * 1000;

/** A passphrase-protected private key to load into the run's ssh-agent. */
export interface AnsibleAgentKey {
  /** Path of the (still encrypted) key file inside the runner container. */
  keyPath: string;
  /** Passphrase (handed to the runner only through the environment, never argv or disk). */
  passphrase: string;
}

const SAFE_RUNNER_PATH = /^\/[A-Za-z0-9_./-]+$/;

/**
 * Shell wrapper (run inside the runner, under `ssh-agent`) that loads the passphrase-protected
 * keys into the agent and then runs "$@" (ansible-playbook ...). Each passphrase comes from an
 * environment variable SEGMENTRA_KP_<n> (forwarded with `docker exec -e NAME`, value taken from
 * the docker client's environment) and is piped to ssh-add with the shell builtin printf, so it
 * never appears in argv or on disk. The agent (and the decrypted keys) exits with the playbook.
 */
export function ansibleAgentWrapper(keys: Array<{ keyPath: string }>): string {
  const lines = ['set -u'];
  keys.forEach((k, i) => {
    if (!SAFE_RUNNER_PATH.test(k.keyPath) || k.keyPath.split('/').includes('..')) throw new Error(`Unsafe runner key path: ${k.keyPath}`);
    lines.push(
      `printf '%s\\n' "$SEGMENTRA_KP_${i}" | ssh-add -q '${k.keyPath}' >/dev/null 2>&1 || { echo "segmentra: could not load SSH key ${k.keyPath} into ssh-agent (wrong key passphrase?)" >&2; exit 1; }`,
      `unset SEGMENTRA_KP_${i}`
    );
  });
  lines.push('"$@"');
  return lines.join('\n');
}

export async function runAnsiblePlaybook(params: {
  runnerContainer: string;
  inventoryPath: string; // path inside runner container
  playbookPath: string; // path inside runner container
  extraEnv?: Record<string, string>;
  /**
   * Passphrase-protected keys: the playbook then runs under `ssh-agent` inside the runner
   * with these keys loaded (see ansibleAgentWrapper). Keys without a passphrase need nothing.
   */
  agentKeys?: AnsibleAgentKey[];
  stdoutPath?: string; // host filesystem path
  stderrPath?: string; // host filesystem path
  /** Overall timeout in ms (default 30 minutes). The playbook is killed when exceeded. */
  timeoutMs?: number;
}): Promise<{ exitCode: number; command: string; timedOut?: boolean; error?: string }> {
  const timeoutMs = params.timeoutMs && params.timeoutMs > 0 ? params.timeoutMs : DEFAULT_ANSIBLE_TIMEOUT_MS;
  const timeoutSec = Math.ceil(timeoutMs / 1000);
  const ansibleArgs = ['ansible-playbook', '-i', params.inventoryPath, params.playbookPath];
  const agentKeys = params.agentKeys ?? [];
  const secretEnv: Record<string, string> = {};
  const envFlags: string[] = [];
  let runArgs = ansibleArgs;
  if (agentKeys.length > 0) {
    agentKeys.forEach((k, i) => {
      secretEnv[`SEGMENTRA_KP_${i}`] = k.passphrase;
      envFlags.push('-e', `SEGMENTRA_KP_${i}`); // name only: docker reads the value from its own env
    });
    // Keys expire from the agent shortly after the run's timeout even if something is left behind.
    runArgs = ['ssh-agent', '-t', String(timeoutSec + 120), 'sh', '-c', ansibleAgentWrapper(agentKeys), 'segmentra-ansible', ...ansibleArgs];
  }
  // `timeout` runs inside the container so the playbook itself is killed, not just the docker client.
  const args = ['exec', ...envFlags, params.runnerContainer, 'timeout', '--kill-after=30', String(timeoutSec), ...runArgs];

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
      env: { ...process.env, ...(params.extraEnv ?? {}), ...secretEnv },
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
