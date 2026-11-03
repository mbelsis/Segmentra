#!/usr/bin/env node
// Runs a lab of scripts/demo-lab.py from start to finish on a disposable Segmentra: up, its feature
// checks, down, and then verifies that nothing is left behind. What users run is what is tested.
//
//   node tests/labs/run.mjs <lab> [--keep]      (API on http://127.0.0.1:18083, login admin/admin123)
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');
const composeFile = path.join(here, 'docker-compose.yml');
const projectName = 'segmentra-labtest';
const apiBase = 'http://127.0.0.1:18083/api';
const LABS = {
  base: { stateFile: '.demo-lab.json', containers: ['test-a', 'test-b', 'test-c', 'test-syslog'], networks: ['segmentra-demo-lab'], checks: false },
  iot: { stateFile: '.demo-lab-iot.json', containers: ['iot-gw', 'iot-hmi', 'iot-eng', 'iot-office', 'iot-plc', 'iot-rtu', 'iot-sensor', 'iot-camera', 'iot-printer'], networks: ['segmentra-iot-it', 'segmentra-iot-ot'], checks: true },
  swarm: { stateFile: '.demo-lab-swarm.json', containers: ['swarm-m1', 'swarm-m2', 'swarm-m3', 'swarm-w1', 'swarm-w2', 'swarm-client-a', 'swarm-client-b'], networks: ['segmentra-swarm'], checks: true },
};
const keep = process.argv.includes('--keep');
const labName = process.argv.slice(2).find((a) => !a.startsWith('--'));
const lab = LABS[labName];
if (!lab) {
  console.error(`Usage: node tests/labs/run.mjs <${Object.keys(LABS).join('|')}> [--keep]`);
  process.exit(2);
}

function run(command, args, { allowFailure = false, show = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: repoRoot, stdio: ['ignore', show ? 'inherit' : 'pipe', show ? 'inherit' : 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout?.on('data', (d) => { stdout += d; });
    child.stderr?.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0 || allowFailure) resolve({ code: code ?? 0, stdout, stderr });
      else reject(new Error(`${command} ${args.join(' ')} failed (${code})\n${stderr || stdout}`));
    });
  });
}
const compose = (...a) => run('docker', ['compose', '-f', composeFile, '-p', projectName, ...a]);
const python = process.platform === 'win32' ? 'python' : 'python3';
const labCommand = (command, ...extra) => run(python, [
  path.join('scripts', 'demo-lab.py'), command, '--lab', labName, '--api-url', apiBase, '--password', 'admin123', ...extra,
], { show: true });

async function apiGet(token, p) {
  const res = await fetch(apiBase + p, { headers: { authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`GET ${p} -> ${res.status}`);
  return res.json();
}

async function startSegmentra() {
  console.log(`[labs] Starting a disposable Segmentra (project ${projectName})`);
  await compose('down', '-v', '--remove-orphans');
  await compose('up', '-d', '--build');
  for (let i = 0; i < 90; i += 1) {
    try { if ((await fetch(`${apiBase}/health`)).ok) return; } catch { /* still starting */ }
    await delay(2000);
  }
  throw new Error(`The API did not become healthy:\n${(await compose('logs', '--tail', '30', 'api')).stdout}`);
}

/** After `down` the disposable Segmentra must be as the lab found it, apart from history it keeps on purpose. */
async function verifyNothingLeft() {
  const login = await fetch(`${apiBase}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin123' }) });
  const { token } = await login.json();
  const hosts = (await apiGet(token, '/hosts?limit=1000')).hosts.filter((h) => h.enabled);
  const credentials = (await apiGet(token, '/ssh-credentials')).sshCredentials;
  const assets = (await apiGet(token, '/iot-assets')).assets;
  const leftovers = [];
  if (hosts.length) leftovers.push(`enabled hosts: ${hosts.map((h) => h.hostname)}`);
  if (credentials.length) leftovers.push(`credentials: ${credentials.map((c) => c.name)}`);
  if (assets.length) leftovers.push(`IoT assets: ${assets.map((a) => a.name)}`);
  for (const name of lab.containers) {
    if ((await run('docker', ['inspect', name], { allowFailure: true })).code === 0) leftovers.push(`container ${name}`);
  }
  for (const name of lab.networks) {
    if ((await run('docker', ['network', 'inspect', name], { allowFailure: true })).code === 0) leftovers.push(`network ${name}`);
  }
  if (existsSync(path.join(repoRoot, lab.stateFile))) leftovers.push(`state file ${lab.stateFile}`);
  if (leftovers.length) throw new Error(`down left things behind: ${leftovers.join('; ')}`);
  console.log('[labs] down removed everything');
}

async function main() {
  if (existsSync(path.join(repoRoot, lab.stateFile))) {
    throw new Error(`The ${labName} lab is already up from this folder (${lab.stateFile}). It uses fixed container names, so run "python3 scripts/demo-lab.py down --lab ${labName}" first.`);
  }
  await run('docker', ['version']);
  await startSegmentra();
  await labCommand('up', '--set-executor-ssh');
  if (lab.checks) await labCommand('check');
  await run(python, [path.join('scripts', 'demo-lab.py'), 'traffic', '--lab', labName], { show: true });
  if (keep) {
    console.log(`[labs] Leaving the lab running (--keep). API on ${apiBase}`);
    return;
  }
  await labCommand('down');
  await verifyNothingLeft();
  await compose('down', '-v', '--remove-orphans');
  console.log(`[labs] The ${labName} lab passed`);
}

main().catch(async (e) => {
  console.error(e.message);
  process.exitCode = 1;
  if (!keep) console.error(`[labs] Left running so you can look at it. Clean up with: python3 scripts/demo-lab.py down --lab ${labName} --api-url ${apiBase} --password admin123; docker compose -f tests/labs/docker-compose.yml -p ${projectName} down -v`);
});
