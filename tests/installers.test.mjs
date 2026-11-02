import assert from 'node:assert/strict';
import { test } from 'node:test';

import { devDatabaseUrl, parseDotEnv } from '../packages/db/scripts/dev-env.js';

test('parseDotEnv handles CRLF, a BOM, quotes and comments', () => {
  assert.deepEqual(parseDotEnv('﻿A=1\r\n# note\r\nB="two"\nC=\'three\'\nD=a=b\n\nnot a line\n'), {
    A: '1',
    B: 'two',
    C: 'three',
    D: 'a=b',
  });
});

test('database URL defaults to the local development database', () => {
  assert.equal(devDatabaseUrl({}, {}), 'postgres://segmentra:segmentra@127.0.0.1:15432/segmentra');
});

test('database URL follows .env, like docker compose does', () => {
  assert.equal(
    devDatabaseUrl({}, { POSTGRES_PASSWORD: 'abc', DB_PASSWORD: 'ignored', DB_PORT: '5555', DB_USER: 'u', DB_NAME: 'n' }),
    'postgres://u:abc@127.0.0.1:5555/n',
  );
  assert.equal(devDatabaseUrl({}, { DB_PASSWORD: 'fallback' }), 'postgres://segmentra:fallback@127.0.0.1:15432/segmentra');
});

test('the environment wins over .env, and SEGMENTRA_DATABASE_URL over everything', () => {
  assert.equal(devDatabaseUrl({ POSTGRES_PASSWORD: 'env' }, { POSTGRES_PASSWORD: 'file' }), 'postgres://segmentra:env@127.0.0.1:15432/segmentra');
  assert.equal(devDatabaseUrl({ SEGMENTRA_DATABASE_URL: 'postgres://x/y' }, { POSTGRES_PASSWORD: 'file' }), 'postgres://x/y');
});

test('passwords are encoded, including characters start.bat would eat', () => {
  assert.equal(devDatabaseUrl({}, { POSTGRES_PASSWORD: 'a b@c/d!e' }), 'postgres://segmentra:a%20b%40c%2Fd%21e@127.0.0.1:15432/segmentra');
});
