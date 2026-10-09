#!/usr/bin/env node
// segmentra-policy: policy as code for Segmentra (see docs/policy-as-code.md). No dependencies.
//
//   segmentra-policy export <name|id> [--format yaml|json] [--version latest|N] [-o file]
//   segmentra-policy export --all -d <dir> [--format yaml|json]
//   segmentra-policy plan  <file|dir>... [--detailed-exitcode]   dry run: what an apply would do
//   segmentra-policy apply <file|dir>... [--update-scope]        create / add a DRAFT version (never approves)
//
// Connection: SEGMENTRA_URL (default http://localhost:8080) and SEGMENTRA_TOKEN, or SEGMENTRA_USER + SEGMENTRA_PASSWORD.
// Exit codes: 0 ok (plan: nothing to do, or no --detailed-exitcode), 1 error or invalid document, 2 plan --detailed-exitcode: changes pending.
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, extname, join } from 'node:path';

const args = process.argv.slice(2);
const cmd = args.shift();
const flag = (name) => { const i = args.indexOf(name); if (i < 0) return false; args.splice(i, 1); return true; };
const opt = (name, short) => {
  for (const n of [name, short].filter(Boolean)) { const i = args.indexOf(n); if (i >= 0) { const v = args[i + 1]; args.splice(i, 2); return v; } }
  return undefined;
};
const base = (process.env.SEGMENTRA_URL ?? 'http://localhost:8080').replace(/\/$/, '') + '/api';
const die = (msg, code = 1) => { console.error(`segmentra-policy: ${msg}`); process.exit(code); };

async function token() {
  if (process.env.SEGMENTRA_TOKEN) return process.env.SEGMENTRA_TOKEN;
  const { SEGMENTRA_USER: username, SEGMENTRA_PASSWORD: password } = process.env;
  if (!username || !password) die('set SEGMENTRA_TOKEN, or SEGMENTRA_USER and SEGMENTRA_PASSWORD');
  const r = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username, password }) });
  if (!r.ok) die(`login failed (${r.status})`);
  return (await r.json()).token;
}

function filesIn(paths) {
  const out = [];
  for (const p of paths) {
    let st; try { st = statSync(p); } catch { die(`cannot read ${p}`); }
    if (st.isDirectory()) {
      for (const f of readdirSync(p).sort()) if (['.yaml', '.yml', '.json'].includes(extname(f).toLowerCase())) out.push(join(p, f));
    } else out.push(p);
  }
  if (!out.length) die('no policy files found');
  return out;
}

/** A YAML file may hold several documents separated by "---" lines. */
function splitDocuments(text, file) {
  if (extname(file).toLowerCase() === '.json') return [text];
  return text.split(/^---\s*$/m).map((d) => d.trim()).filter((d) => d && d.split('\n').some((l) => l.trim() && !l.trim().startsWith('#')));
}

function show(file, r) {
  const where = `${file}${r.name ? ` (${r.name})` : ''}`;
  const verb = { created: 'create', new_version: 'new DRAFT version', unchanged: 'no change' }[r.action] ?? r.action;
  console.log(`${r.dryRun ? 'plan ' : 'apply'}: ${where}: ${verb}${r.versionNumber ? ` v${r.versionNumber}${r.versionStatus ? ` (${r.versionStatus})` : ''}` : ''}`);
  for (const a of r.diff?.added ?? []) console.log(`    + ${a}`);
  for (const d of r.diff?.removed ?? []) console.log(`    - ${d}`);
  if (r.diff?.reordered) console.log('    ~ rules reordered');
  for (const w of r.warnings ?? []) console.log(`    ! ${w}`);
}

async function run() {
  if (!['export', 'plan', 'apply'].includes(cmd ?? '')) {
    console.error(readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 12).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'));
    process.exit(cmd ? 1 : 0);
  }
  const auth = { authorization: `Bearer ${await token()}` };
  const json = async (path) => { const r = await fetch(`${base}${path}`, { headers: auth }); if (!r.ok) die(`${path}: ${r.status} ${await r.text()}`); return r.json(); };

  if (cmd === 'export') {
    const format = opt('--format') ?? 'yaml';
    const version = opt('--version');
    const outFile = opt('-o', '--output');
    const dir = opt('-d', '--dir');
    const all = flag('--all');
    const sets = (await json('/policy-sets')).policySets;
    const pick = all ? sets : sets.filter((s) => s.id === args[0] || s.name === args[0]);
    if (!pick.length) die(all ? 'no policy sets' : `no policy set named or with id "${args[0] ?? ''}"`);
    if (!all && pick.length > 1) die(`${pick.length} policy sets are named "${args[0]}"; use the id`);
    if (all && !dir) die('--all needs -d <dir>');
    if (dir) mkdirSync(dir, { recursive: true });
    for (const s of pick) {
      const q = `?format=${format}${version ? `&version=${encodeURIComponent(version)}` : ''}`;
      const r = await fetch(`${base}/policy-sets/${s.id}/export${q}`, { headers: auth });
      if (!r.ok) { console.error(`export of "${s.name}" failed: ${r.status} ${await r.text()}`); continue; }
      const text = await r.text();
      if (dir) { const f = join(dir, `${s.name.replace(/[^A-Za-z0-9._-]+/g, '_')}.${format === 'json' ? 'json' : 'yaml'}`); writeFileSync(f, text); console.log(`exported ${s.name} v${r.headers.get('x-segmentra-version')} (${r.headers.get('x-segmentra-version-status')}) -> ${f}`); }
      else if (outFile) { writeFileSync(outFile, text); console.log(`exported ${s.name} -> ${outFile}`); }
      else process.stdout.write(text);
    }
    return;
  }

  // plan / apply
  const dryRun = cmd === 'plan';
  const detailed = flag('--detailed-exitcode');
  const updateScope = flag('--update-scope');
  let errors = 0, changes = 0;
  for (const file of filesIn(args)) {
    for (const [i, text] of splitDocuments(readFileSync(file, 'utf8'), file).entries()) {
      const label = i ? `${file}#${i + 1}` : file;
      const r = await fetch(`${base}/policy-sets/import?dryRun=${dryRun}&updateScope=${updateScope}`, {
        method: 'POST', headers: { ...auth, 'content-type': extname(file).toLowerCase() === '.json' ? 'application/json' : 'application/yaml' }, body: text,
      });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) {
        errors += 1;
        console.error(`${label}: ${body.message ?? r.status}`);
        for (const p of body.problems ?? []) console.error(`    ${p.path}: ${p.message}`);
        continue;
      }
      show(label, body);
      if (body.action !== 'unchanged') changes += 1;
    }
  }
  if (errors) process.exit(1);
  console.log(`${changes} policy set(s) ${dryRun ? 'would change' : 'changed'}${dryRun ? '' : '; the new versions are DRAFTs and still need approval'}`);
  if (dryRun && detailed && changes) process.exit(2);
}

run().catch((e) => die(e.message));
