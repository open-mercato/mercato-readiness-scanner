import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { loadEnvironment, weakSecret } from '../../src/environment.js'
import { existsInside, readProductionEnvText } from '../../src/files.js'

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'readiness-env-'))
  return { root, load: (env: Record<string, string | undefined> = {}) => loadEnvironment(root, (file) => fs.existsSync(path.join(root, file)), env) }
}

test('production env precedence ends with inherited process values, including explicitly empty values', () => {
  const { root, load } = fixture()
  try {
    fs.writeFileSync(path.join(root, '.env'), 'JWT_SECRET=base\nNODE_ENV=development')
    fs.writeFileSync(path.join(root, '.env.production'), 'JWT_SECRET=production')
    fs.writeFileSync(path.join(root, '.env.local'), 'JWT_SECRET=local')
    fs.writeFileSync(path.join(root, '.env.production.local'), 'JWT_SECRET=production-local')
    assert.equal(load().values.get('JWT_SECRET'), 'production-local')
    assert.equal(load({ JWT_SECRET: 'inherited' }).values.get('JWT_SECRET'), 'inherited')
    assert.equal(load({ JWT_SECRET: '' }).values.get('JWT_SECRET'), '')
    assert.equal(load({ UNRELATED_TOKEN: 'must-not-load' }).values.has('UNRELATED_TOKEN'), false)
    assert.equal(load({ DOCUMENTS_COLLAB_JWT_SECRET_V2: 'collab' }).values.get('DOCUMENTS_COLLAB_JWT_SECRET_V2'), 'collab')
    assert.deepEqual(load({ NODE_ENV: 'production' }).sources, ['.env', '.env.production', '.env.local', '.env.production.local', 'process environment'])
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
})

test('parses quoted dotenv values and expands references without executing commands', () => {
  const { root, load } = fixture()
  try {
    fs.writeFileSync(path.join(root, '.env'), [
      'export NODE_ENV="production" # comment',
      'POSTGRES_PASSWORD="a#quoted-password"',
      'DATABASE_URL=postgresql://app:${POSTGRES_PASSWORD}@db/app',
      'JWT_SECRET=$(touch SHOULD_NOT_EXIST)',
      'CYCLE_A=${CYCLE_B}', 'CYCLE_B=${CYCLE_A}',
    ].join('\n'))
    const env = load()
    assert.equal(env.values.get('NODE_ENV'), 'production')
    assert.equal(env.values.get('POSTGRES_PASSWORD'), 'a#quoted-password')
    assert.equal(env.values.get('DATABASE_URL'), 'postgresql://app:a#quoted-password@db/app')
    assert.equal(env.values.get('JWT_SECRET'), '$(touch SHOULD_NOT_EXIST)')
    assert.match(env.values.get('CYCLE_A') ?? '', /\$\{/)
    assert.equal(fs.existsSync(path.join(root, 'SHOULD_NOT_EXIST')), false)
    const overridden = load({ POSTGRES_PASSWORD: 'inherited-password' })
    assert.equal(overridden.values.get('DATABASE_URL'), 'postgresql://app:inherited-password@db/app')
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
})

test('does not treat sanitized examples as deployed secrets or read non-allowlisted env files', () => {
  const { root, load } = fixture()
  try {
    fs.writeFileSync(path.join(root, '.env.example'), 'JWT_SECRET=example')
    fs.writeFileSync(path.join(root, '.env.staging'), 'JWT_SECRET=not-production')
    assert.equal(load().values.has('JWT_SECRET'), false)
    assert.equal(readProductionEnvText(root, '.env.staging'), null)
    assert.equal(readProductionEnvText(root, '../.env'), null)
    assert.equal(existsInside(root, '.env.example'), true)
    fs.symlinkSync(path.join(root, '.env.example'), path.join(root, '.env.production'))
    assert.deepEqual(load().unreadableFiles, ['.env.production'])
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
})

test('weak-secret checks reject defaults, short secrets, repeated characters, and substitutions', () => {
  for (const value of [undefined, '', 'postgres', 'change-me-dev-secret', 'a'.repeat(64), '${JWT_SECRET}', 'example'.repeat(20)]) assert.equal(weakSecret(value), true)
  assert.equal(weakSecret('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'), false)
})
