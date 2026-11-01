// Regression tests for deep audit round 5 (infrastructure / operations):
//   1. the seed creates "admin" only on a fresh database (never re-creates a deleted/renamed admin),
//   2. the hardened override gives the SSH_ASKPASS helper an exec tmpfs (and keeps /tmp noexec),
//   3. nginx security headers, 25 MB API bodies, dynamic upstream resolution,
//   4. segmentra-backup.sh validates before dropping and restores in one transaction (umask 077),
//   5. run.sh / install.sh keep the hardened override via COMPOSE_FILE in .env,
//   6. the demo loader refuses non-local / non-demo databases without --force.
//
//   node --test tests/audit-r5-infra.test.mjs
//
// Static checks always run. Checks that need Docker (compose config, nginx -t, a throw-away
// PostgreSQL for the seed / demo loader / backup round trip) are skipped when Docker is not
// available; set SEGMENTRA_R5_SKIP_DOCKER=1 to skip them explicitly.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const run = (cmd, args, opts = {}) =>
  spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', timeout: 180_000, ...opts });

const hasBash = run('bash', ['-c', 'true']).status === 0;
const hasDocker =
  process.env.SEGMENTRA_R5_SKIP_DOCKER !== '1' && run('docker', ['info'], { timeout: 20_000 }).status === 0;
const hasCompose = hasDocker && run('docker', ['compose', 'version']).status === 0;
const noDocker = hasDocker ? false : 'Docker not available';

// ------------------------------------------------------------------------------ 1. seed
test('seed: initial admin only when the users table is empty', () => {
  const src = read('packages/db/scripts/seed-roles.js');
  assert.match(src, /SELECT COUNT\(\*\)::int AS n FROM users/);
  assert.match(src, /Initial admin bootstrap skipped/);
  assert.match(src, /pg_advisory_xact_lock/);
  assert.doesNotMatch(src, /SELECT id FROM users WHERE username=\$1', \['admin'\]/);
});

// ------------------------------------------------------------------------------ 2. askpass tmpfs
test('hardened override: exec tmpfs for the askpass helper, /tmp stays noexec', () => {
  const y = read('docker-compose.hardened.yml');
  assert.match(y, /SEGMENTRA_ASKPASS_DIR: \/run\/segmentra-askpass/);
  assert.match(y, /- \/run\/segmentra-askpass:size=1m,mode=0700,uid=1000,gid=1000,exec/);
  const tmpLine = y.split('\n').find((l) => /^\s*- \/tmp:size=64m/.test(l));
  assert.ok(tmpLine && !/\bexec\b/.test(tmpLine), '/tmp of segmentra-app must not be exec');
});

test('compose: hardened config renders askpass tmpfs + env', { skip: hasCompose ? false : 'docker compose not available' }, () => {
  for (const args of [['config', '-q'], ['-f', 'docker-compose.yml', '-f', 'docker-compose.hardened.yml', 'config', '-q']]) {
    const r = run('docker', ['compose', ...args]);
    assert.equal(r.status, 0, r.stderr);
  }
  const r = run('docker', ['compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.hardened.yml', 'config', '--format', 'json']);
  assert.equal(r.status, 0, r.stderr);
  const app = JSON.parse(r.stdout).services['segmentra-app'];
  assert.equal(app.environment.SEGMENTRA_ASKPASS_DIR, '/run/segmentra-askpass');
  assert.ok(app.tmpfs.some((t) => t.startsWith('/run/segmentra-askpass:') && t.endsWith(',exec')));
  assert.equal(app.read_only, true);
});

test('askpass helper executes as uid 1000 on the exec tmpfs, not on /tmp', { skip: noDocker }, () => {
  const script = [
    'set -e',
    'for d in /run/segmentra-askpass /tmp; do',
    '  dir=$(mktemp -d "$d/segmentra-askpass-XXXXXX"); chmod 700 "$dir"',
    '  printf "#!/bin/sh\\necho ok\\n" > "$dir/askpass.sh"; chmod 700 "$dir/askpass.sh"',
    '  if out=$("$dir/askpass.sh" 2>/dev/null); then echo "$d:$out"; else echo "$d:denied"; fi',
    'done',
    'id -u'
  ].join('\n');
  const r = run('docker', [
    'run', '--rm', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--user', '1000:1000',
    '--tmpfs', '/tmp:size=64m,mode=1777',
    '--tmpfs', '/run/segmentra-askpass:size=1m,mode=0700,uid=1000,gid=1000,exec',
    'alpine:3', 'sh', '-c', script
  ]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /\/run\/segmentra-askpass:ok/);
  assert.match(r.stdout, /\/tmp:denied/);
  assert.match(r.stdout, /^1000$/m);
});

// ------------------------------------------------------------------------------ 3. nginx
test('nginx: headers (always), body limit, dynamic upstream', () => {
  const conf = read('infra/web/nginx.conf');
  const hdr = read('infra/web/security-headers.conf');
  for (const h of ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']) {
    assert.match(hdr, new RegExp(`add_header ${h} "[^"]+" always;`), h);
  }
  assert.match(hdr, /frame-ancestors 'none'/);
  assert.match(hdr, /script-src 'self';/);
  assert.match(conf, /client_max_body_size 25m;/);
  assert.match(conf, /resolver 127\.0\.0\.11 valid=10s/);
  assert.match(conf, /set \$segmentra_api http:\/\/segmentra-app:8080;/);
  assert.match(conf, /proxy_pass \$segmentra_api;/);
  // every static location that sets its own add_header must include the security headers
  const statics = conf.split('location').slice(1).filter((b) => !b.includes('/api/'));
  for (const b of statics) assert.match(b, /include \/etc\/nginx\/segmentra\/security-headers\.conf;/);
  assert.match(read('infra/web/Dockerfile'), /COPY infra\/web\/security-headers\.conf \/etc\/nginx\/segmentra\/security-headers\.conf/);
  // the built SPA must not need inline scripts (script-src 'self')
  const index = path.join(ROOT, 'apps/web/dist/index.html');
  if (fs.existsSync(index)) {
    const html = fs.readFileSync(index, 'utf8');
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      assert.match(m[1], /\bsrc=/, 'inline <script> in index.html would be blocked by the CSP');
    }
  }
});

test('nginx -t accepts the config', { skip: noDocker }, () => {
  const net = `segr5-test-${process.pid}`;
  run('docker', ['network', 'create', net]);
  try {
    const r = run('docker', [
      'run', '--rm', '--network', net,
      '-v', `${path.join(ROOT, 'infra/web/nginx.conf')}:/etc/nginx/conf.d/default.conf:ro`,
      '-v', `${path.join(ROOT, 'infra/web/security-headers.conf')}:/etc/nginx/segmentra/security-headers.conf:ro`,
      'nginx:alpine', 'nginx', '-t'
    ]);
    assert.equal(r.status, 0, r.stderr);
  } finally {
    run('docker', ['network', 'rm', net]);
  }
});

// ------------------------------------------------------------------------------ 4/5. shell scripts
test('shell scripts parse (bash -n)', { skip: hasBash ? false : 'bash not available' }, () => {
  for (const f of ['scripts/segmentra-backup.sh', 'run.sh', 'install.sh', 'start.sh', 'infra/app/docker-entrypoint.sh']) {
    const r = run('bash', ['-n', f]);
    assert.equal(r.status, 0, `${f}: ${r.stderr}`);
  }
});

test('backup script: umask 077, validation before drop, single transaction', () => {
  const s = read('scripts/segmentra-backup.sh');
  assert.match(s, /^umask 077$/m);
  assert.match(s, /mkdir -p -m 700/);
  assert.match(s, /gunzip -t/);
  assert.match(s, /-- PostgreSQL database dump complete/);
  assert.match(s, /--single-transaction/);
  // the DROP is part of the same psql stream, not a separate -c call
  assert.doesNotMatch(s, /-c "DROP SCHEMA/);
  assert.ok(s.indexOf('gunzip -t') < s.indexOf("'DROP SCHEMA public CASCADE;'"));
});

test('run.sh / install.sh keep the hardened override via COMPOSE_FILE', () => {
  const runSh = read('run.sh');
  const inst = read('install.sh');
  assert.match(runSh, /--hardened\) HARDENED_FLAG=1/);
  assert.match(runSh, /COMPOSE_FILE=\$HARDENED_COMPOSE_FILE/);
  assert.match(runSh, /ReadonlyRootfs/);
  assert.match(inst, /--hardened\) HARDENED=1/);
  assert.match(inst, /echo "COMPOSE_FILE=\$HARDENED_COMPOSE_FILE" >> \.env/);
  for (const s of [runSh, inst]) assert.match(s, /HARDENED_COMPOSE_FILE="docker-compose\.yml:docker-compose\.hardened\.yml"/);
});

test('run.sh --hardened records COMPOSE_FILE once and compose honours it', { skip: hasCompose && hasBash ? false : 'docker compose / bash not available' }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'segr5-run-'));
  try {
    for (const f of ['docker-compose.yml', 'docker-compose.hardened.yml', 'run.sh']) fs.copyFileSync(path.join(ROOT, f), path.join(dir, f));
    fs.writeFileSync(path.join(dir, '.env'), 'JWT_SECRET=x');
    const env = { ...process.env };
    delete env.COMPOSE_FILE;
    for (let i = 0; i < 2; i++) {
      const r = run('bash', ['./run.sh', '--status', '--production', '--hardened'], { cwd: dir, env });
      assert.equal(r.status, 0, r.stderr + r.stdout);
    }
    const dotenv = fs.readFileSync(path.join(dir, '.env'), 'utf8');
    assert.equal(dotenv.match(/^COMPOSE_FILE=docker-compose\.yml:docker-compose\.hardened\.yml$/gm)?.length, 1);
    const cfg = run('docker', ['compose', 'config', '--format', 'json'], { cwd: dir, env });
    assert.equal(cfg.status, 0, cfg.stderr);
    const app = JSON.parse(cfg.stdout).services['segmentra-app'];
    assert.equal(app.read_only, true);
    assert.ok(!(app.volumes || []).some((v) => String(v.source).includes('docker.sock')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------------------ 6. demo loader
test('demo loader refuses a non-local DATABASE_URL without --force', () => {
  for (const url of ['postgres://u:p@db.example.com:5432/segmentra', 'postgres://u:p@10.0.0.5/segmentra']) {
    const r = run(process.execPath, ['packages/db/scripts/load-demo.js'], {
      env: { ...process.env, DATABASE_URL: url, NODE_ENV: 'development', SEGMENTRA_DEMO_FORCE: '' }
    });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /non-local database/);
  }
  const prod = run(process.execPath, ['packages/db/scripts/load-demo.js'], {
    env: { ...process.env, DATABASE_URL: 'postgres://u:p@127.0.0.1:1/x', NODE_ENV: 'production', SEGMENTRA_DEMO_FORCE: '' }
  });
  assert.equal(prod.status, 1);
  assert.match(prod.stderr, /NODE_ENV=production/);
});

// ------------------------------------------------------------------------------ PostgreSQL-backed checks
function startPostgres(name) {
  const r = run('docker', [
    'run', '-d', '--rm', '--name', name, '-e', 'POSTGRES_USER=segmentra', '-e', 'POSTGRES_PASSWORD=segmentra',
    '-e', 'POSTGRES_DB=segmentra', '-p', '127.0.0.1::5432', 'postgres:16'
  ]);
  assert.equal(r.status, 0, r.stderr);
  const port = run('docker', ['port', name, '5432/tcp']).stdout.trim().split('\n')[0].split(':').pop();
  for (let i = 0; i < 60; i++) {
    // pg_isready inside the container answers before the init scripts finish; probe twice
    const ok = run('docker', ['exec', name, 'psql', '-U', 'segmentra', '-h', '127.0.0.1', '-tAc', 'SELECT 1']);
    if (ok.status === 0 && ok.stdout.trim() === '1') return `postgres://segmentra:segmentra@127.0.0.1:${port}/segmentra`;
    spawnSync('sleep', ['1']);
  }
  throw new Error('PostgreSQL did not become ready');
}
const psql = (name, sql) => run('docker', ['exec', '-i', name, 'psql', '-U', 'segmentra', '-tA', '-v', 'ON_ERROR_STOP=1'], { input: sql });

test('seed + demo loader against a throw-away PostgreSQL', { skip: noDocker, timeout: 240_000 }, () => {
  const name = `segr5-pg-${process.pid}`;
  try {
    const url = startPostgres(name);
    const node = (script, env = {}, args = []) =>
      run(process.execPath, [script, ...args], { env: { ...process.env, DATABASE_URL: url, SEGMENTRA_DEMO_FORCE: '', ...env } });
    const mig = node('packages/db/scripts/migrate.js', {}, ['up']);
    assert.equal(mig.status, 0, mig.stderr + mig.stdout);

    // production, fresh DB, no password: nothing created
    let r = node('packages/db/scripts/seed-roles.js', { NODE_ENV: 'production', SEGMENTRA_ADMIN_PASSWORD: '' });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(psql(name, 'SELECT count(*) FROM users').stdout.trim(), '0');

    // development, fresh DB: admin/admin123 as before
    r = node('packages/db/scripts/seed-roles.js', { NODE_ENV: 'development', SEGMENTRA_ADMIN_PASSWORD: '' });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Created default admin user/);

    // hardening: create own admin, delete "admin" -> a restart must not bring it back
    assert.equal(psql(name, `
      INSERT INTO users (username, display_name, password_hash, is_active) VALUES ('ops-admin', 'Ops', 'x', true);
      INSERT INTO user_roles (user_id, role_id) SELECT u.id, r.id FROM users u, roles r WHERE u.username='ops-admin' AND r.name='admin';
      DELETE FROM user_roles WHERE user_id IN (SELECT id FROM users WHERE username='admin');
      DELETE FROM users WHERE username='admin';`).status, 0);
    r = node('packages/db/scripts/seed-roles.js', { NODE_ENV: 'production', SEGMENTRA_ADMIN_PASSWORD: 'a-long-password-from-env' });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Initial admin bootstrap skipped/);
    assert.equal(psql(name, `SELECT count(*) FROM users WHERE username='admin'`).stdout.trim(), '0');

    // demo loader: the DB has a non-demo user -> refused without --force, loaded with it
    r = node('packages/db/scripts/load-demo.js', { NODE_ENV: 'development' });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /looks like a real installation/);
    r = node('packages/db/scripts/load-demo.js', { NODE_ENV: 'development' }, ['--force']);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Demo data loaded/);
    r = node('packages/db/scripts/load-demo.js', { NODE_ENV: 'development' }, ['--remove']);
    assert.equal(r.status, 0, r.stderr);
  } finally {
    run('docker', ['rm', '-f', name]);
  }
});

test('backup script: dump -> restore round trip, failed restore keeps the old DB', { skip: hasCompose && hasBash ? false : 'docker compose / bash not available', timeout: 240_000 }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'segr5-bk-'));
  const project = `segr5bk${process.pid}`;
  const env = { ...process.env, COMPOSE_PROJECT_NAME: project };
  delete env.COMPOSE_FILE;
  const compose = (...a) => run('docker', ['compose', ...a], { cwd: dir, env });
  const q = (sql) => run('docker', ['compose', 'exec', '-T', 'segmentra-db', 'psql', '-U', 'segmentra', '-tA', '-q', '-v', 'ON_ERROR_STOP=1'], { cwd: dir, env, input: sql });
  try {
    fs.mkdirSync(path.join(dir, 'scripts'));
    fs.copyFileSync(path.join(ROOT, 'scripts/segmentra-backup.sh'), path.join(dir, 'scripts/segmentra-backup.sh'));
    fs.writeFileSync(path.join(dir, 'docker-compose.yml'),
      'services:\n  segmentra-db:\n    image: postgres:16\n    environment: { POSTGRES_USER: segmentra, POSTGRES_PASSWORD: x, POSTGRES_DB: segmentra }\n');
    assert.equal(compose('up', '-d').status, 0);
    let ready = false;
    for (let i = 0; i < 60 && !ready; i++) {
      ready = q('SELECT 1').stdout.trim() === '1';
      if (!ready) spawnSync('sleep', ['1']);
    }
    assert.ok(ready, 'postgres not ready');
    assert.equal(q(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
      CREATE TABLE t (id uuid PRIMARY KEY DEFAULT uuid_generate_v4(), name text);
      INSERT INTO t (name) VALUES ('alice'), ('bob');`).status, 0);
    const bk = (...a) => run('bash', ['scripts/segmentra-backup.sh', ...a], { cwd: dir, env, input: '' });

    let r = bk('dump');
    assert.equal(r.status, 0, r.stderr);
    const backups = path.join(dir, 'backups');
    assert.equal(fs.statSync(backups).mode & 0o777, 0o700);
    const file = path.join(backups, fs.readdirSync(backups).find((f) => f.endsWith('.sql.gz')));
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);

    q(`INSERT INTO t (name) VALUES ('carol');`);
    r = bk('restore', file);
    assert.equal(r.status, 1, 'restore without --yes and without a terminal must refuse');
    assert.equal(q('SELECT count(*) FROM t').stdout.trim(), '3');

    r = bk('restore', file, '--yes');
    assert.equal(r.status, 0, r.stderr);
    assert.equal(q(`SELECT string_agg(name, ',' ORDER BY name) FROM t`).stdout.trim(), 'alice,bob');

    // truncated gzip and non-dump files are rejected before anything is dropped
    const trunc = path.join(dir, 'trunc.sql.gz');
    fs.writeFileSync(trunc, fs.readFileSync(file).subarray(0, 100));
    assert.equal(bk('restore', trunc, '--yes').status, 1);
    const notDump = path.join(dir, 'evil.sql');
    fs.writeFileSync(notDump, 'DROP TABLE t;\n');
    assert.equal(bk('restore', notDump, '--yes').status, 1);
    assert.equal(q('SELECT count(*) FROM t').stdout.trim(), '2');

    // a dump that fails half-way rolls back, including the DROP SCHEMA
    const plain = run('bash', ['-c', `gunzip -c "${file}"`]).stdout;
    const broken = path.join(dir, 'broken.sql');
    fs.writeFileSync(broken, plain.replace(/^COPY public\.t /m, 'SELECT no_such_function();\nCOPY public.t '));
    q(`INSERT INTO t (name) VALUES ('dave');`);
    r = bk('restore', broken, '--yes');
    assert.equal(r.status, 1);
    assert.equal(q(`SELECT string_agg(name, ',' ORDER BY name) FROM t`).stdout.trim(), 'alice,bob,dave');
  } finally {
    compose('down', '-v');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
