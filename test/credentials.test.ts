import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { readSafeText } from '../src/files.js'
import { createScanContext } from '../src/app.js'
import { inspectLocalCredentials } from '../src/credential-files.js'
import { assessCredentials, credentialKind } from '../src/credentials.js'
import { formatJson, formatMarkdown, formatTerminal } from '../src/formatters.js'
import { scanTarget } from '../src/scan.js'
import { fixtureStatus, makeAppFixture, removeFixture } from './fixture.js'

const KEY = createHash('sha256').update('synthetic-test-signing-key').digest('hex')
const OTHER_KEY = createHash('sha256').update('synthetic-test-encryption-key').digest('hex')
const PASSWORD = 's7!Zq3#Lp9@Vm5&R'
const DATABASE = `postgres://application:${encodeURIComponent(PASSWORD)}@database.internal/app`

test('classifies credential names without treating public settings and token limits as secrets', () => {
  for (const name of ['JWT_SECRET', 'AUTH_JWT_SECRET', 'DOCUMENTS_COLLAB_JWT_SECRET_V2', 'CUSTOM_WEBHOOK_SECRET']) assert.equal(credentialKind(name), 'signing', name)
  for (const name of ['POSTGRES_PASSWORD', 'PGPASSWORD', 'MYSQL_ROOT_PASSWORD', 'SMTP_PASS', 'password']) assert.equal(credentialKind(name), 'password', name)
  for (const name of ['CUSTOM_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'VAULT_TOKEN', 'CUSTOM_MASTER_KEY', 'clientSecret', 'REDISCLI_AUTH']) assert.equal(credentialKind(name), 'token', name)
  for (const name of ['TENANT_DATA_ENCRYPTION_FALLBACK_KEY', 'TENANT_DATA_ENCRYPTION_KEY', 'KMS_MASTER_KEY', 'FORMS_ENCRYPTION_MASTER_KEY', 'LOOKUP_HASH_PEPPER']) assert.equal(credentialKind(name), 'encryption', name)
  for (const name of ['JWT_EXPIRES_IN', 'JWT_LEGACY_GRACE_MINUTES', 'AWS_ACCESS_KEY_ID', 'VAULT_KV_PATH', 'MCP_SERVER_API_KEY_FILE', 'MAX_OUTPUT_TOKENS', 'OM_SEARCH_STORE_RAW_TOKENS', 'NEXT_PUBLIC_API_KEY', 'STRIPE_PUBLISHABLE_KEY', 'OM_INIT_GENERATE_RANDOM_PASSWORD', 'TENANT_DATA_ENCRYPTION_DEBUG', 'TOKEN_ENDPOINT']) assert.equal(credentialKind(name), null, name)
})

test('rejects JWT defaults, short credentials, predictable patterns, and decoded short keys', () => {
  for (const value of ['', 'secret', 'change-me-dev-auth-secret', 'your-secure-jwt-secret-change-me', 'a'.repeat(64), 'aBcD'.repeat(16), '0123456789abcdef'.repeat(4), 'a'.repeat(31), Buffer.from('syntheticshortkey12345678').toString('base64')]) assert.equal(assessCredentials({ JWT_SECRET: value }).credentials.status, 'fail')
  for (const name of ['POSTGRES_PASSWORD', 'MYSQL_ROOT_PASSWORD', 'SMTP_PASS', 'CUSTOM_TOKEN', 'CUSTOM_API_KEY', 'VAULT_TOKEN']) assert.equal(assessCredentials({ [name]: 'password' }).credentials.status, 'fail', name)
  for (const name of ['PGPASSWORD', 'POSTGRES_PASSWORD', 'MYSQL_ROOT_PASSWORD', 'DATABASE_PASSWORD']) assert.equal(assessCredentials({ [name]: '' }).credentials.status, 'fail')
  assert.equal(assessCredentials({ POSTGRES_PASSWORD: '六个字符密码' }).credentials.status, 'fail')
  assert.equal(assessCredentials({ JWT_SECRET: KEY, DATABASE_URL: DATABASE, CUSTOM_API_KEY: OTHER_KEY }).credentials.status, 'pass')
})

test('inspects encoded URL passwords, query and fragment credentials, DSNs, and JSON credential objects', () => {
  for (const settings of [
    { DATABASE_URL: 'postgres://app:%70%6F%73%74%67%72%65%73@database.internal/app' },
    { REDIS_URL: 'redis://:redis@cache.internal:6379' },
    { SMTP_URL: 'smtp://administrator-prod:administrator-prod@mail.internal' },
    { CUSTOM_URL: 'https://api.internal/?access_token=changeme' },
    { CUSTOM_URL: 'https://api.internal/#password=changeme' },
    { DATABASE_CONNECTION_STRING: "Host=db;User=app;Password='password';Database=app" },
    { API_CREDENTIALS: JSON.stringify({ provider: { password: 'secret' } }) },
  ]) assert.equal(assessCredentials(settings).credentials.status, 'fail')
  for (const settings of [{ REDIS_URL: 'redis://cache.internal:6379' }, { API_CREDENTIALS: '{not-json}' }, { API_CREDENTIALS: '{}' }, { GOOGLE_APPLICATION_CREDENTIALS: '/never/open/credentials.json' }, { DATABASE_URL: 'postgres://app:%invalid@db/app' }]) assert.equal(assessCredentials(settings).credentials.status, 'warning')
})

test('rejects copied template values even when they appear strong and the database host changes', () => {
  const result = assessCredentials({ JWT_SECRET: KEY, DATABASE_URL: DATABASE }, { JWT_SECRET: [OTHER_KEY, KEY], DATABASE_URL: `postgres://template:${encodeURIComponent(PASSWORD)}@localhost/app` })
  assert.equal(result.credentials.status, 'fail')
  assert.match(result.credentials.evidence?.join('\n') ?? '', /JWT_SECRET: matches a credential published/)
  assert.match(result.credentials.evidence?.join('\n') ?? '', /DATABASE_URL: matches a credential published/)
  for (const value of [KEY, PASSWORD]) assert.equal(JSON.stringify(result).includes(value), false)
})

test('fails weak encryption roots and development fallbacks including Compose-style default expansion', () => {
  for (const name of ['TENANT_DATA_ENCRYPTION_FALLBACK_KEY', 'TENANT_DATA_ENCRYPTION_KEY', 'KMS_MASTER_KEY', 'FORMS_ENCRYPTION_MASTER_KEY', 'LOOKUP_HASH_PEPPER']) {
    for (const value of ['dev-tenant-encryption-fallback-key-32chars', 'om-dev-tenant-encryption', '0'.repeat(64), '${ROOT_KEY:-changeme}', 'abcd'.repeat(16)]) assert.equal(assessCredentials({ [name]: value }).encryption.status, 'fail', name)
    assert.equal(assessCredentials({ [name]: OTHER_KEY }).encryption.status, 'pass', name)
    assert.equal(assessCredentials({ [name]: Buffer.from(OTHER_KEY, 'hex').toString('base64') }).encryption.status, 'pass', name)
  }
  assert.equal(assessCredentials({ ALLOW_DERIVED_KMS_FALLBACK: 'true' }).encryption.status, 'fail')
  assert.equal(assessCredentials({ TENANT_DATA_ENCRYPTION: 'no' }).encryption.status, 'fail')
  assert.equal(assessCredentials({ DATABASE_URL: 'postgres://app:${DB_PASSWORD:-postgres}@db/app' }).credentials.status, 'fail')
  assert.equal(assessCredentials({ JWT_SECRET: '${JWT_SECRET}' }).credentials.status, 'warning')
})

test('warns about absent KMS and secret injection without claiming live KMS health', () => {
  const absent = assessCredentials({ TENANT_DATA_ENCRYPTION_FALLBACK_KEY: OTHER_KEY })
  assert.equal(absent.kms.status, 'warning')
  for (const phrase of ['No complete Vault KMS', 'Railway', 'Cloudflare', 'GitHub Actions secrets', 'plaintext .env', 'recovery']) assert.ok(absent.kms.summary.includes(phrase))
  const configured = assessCredentials({ VAULT_ADDR: 'https://vault.internal', VAULT_TOKEN: KEY })
  assert.equal(configured.kms.status, 'warning')
  assert.match(configured.kms.summary, /settings are present; verify live/)
  assert.match(assessCredentials({ VAULT_ADDR: 'invalid', VAULT_TOKEN: KEY }).kms.summary, /No complete/)
})

test('inspects opaque JWT headers without claiming signature verification', () => {
  const header = (alg: string) => Buffer.from(JSON.stringify({ alg })).toString('base64url')
  assert.equal(assessCredentials({ CUSTOM_API_TOKEN: `${header('none')}.e30.` }).credentials.status, 'fail')
  assert.equal(assessCredentials({ CUSTOM_API_TOKEN: `${header('HS256')}.e30.c2lnbmF0dXJl` }).credentials.status, 'warning')
})

test('disabled inspection never opens live files; enabled checks flag weak files with safe runtime overrides', () => {
  const root = makeAppFixture()
  try {
    fs.writeFileSync(path.join(root, '.env.production'), 'JWT_SECRET=change-me-dev-auth-secret\nTENANT_DATA_ENCRYPTION_FALLBACK_KEY=om-dev-tenant-encryption\n')
    const originalOpen = fs.openSync
    fs.openSync = (() => { throw new Error('must not open live configuration by default') }) as typeof fs.openSync
    try { assert.equal(inspectLocalCredentials(root, false, {}).credentials.status, 'skipped') } finally { fs.openSync = originalOpen }
    const before = fixtureStatus(root)
    const result = inspectLocalCredentials(root, true, { JWT_SECRET: KEY, DATABASE_URL: DATABASE, TENANT_DATA_ENCRYPTION_FALLBACK_KEY: OTHER_KEY })
    assert.equal(result.credentials.status, 'fail')
    assert.equal(result.encryption.status, 'fail')
    assert.equal(fixtureStatus(root), before)
    for (const value of [KEY, OTHER_KEY, PASSWORD, 'change-me-dev-auth-secret', 'om-dev-tenant-encryption', root]) assert.equal(JSON.stringify(result).includes(value), false)
  } finally { removeFixture(root) }
})

test('inspects Compose environments and Redis requirepass without expanding or executing anything', () => {
  const root = makeAppFixture()
  try {
    fs.writeFileSync(path.join(root, 'docker-compose.yml'), ['x-env: &defaults', '  POSTGRES_PASSWORD: postgres', 'services:', '  db:', '    environment:', '      <<: *defaults', '  redis:', '    command: ["redis-server", "--requirepass", "redis"]', '  app:', '    environment:', '      - TENANT_DATA_ENCRYPTION_FALLBACK_KEY=${ENCRYPTION_KEY:-om-dev-tenant-encryption}', '    env_file: /must/not/be/opened'].join('\n'))
    const result = inspectLocalCredentials(root, true, {})
    assert.equal(result.credentials.status, 'fail')
    assert.equal(result.encryption.status, 'fail')
    for (const name of ['POSTGRES_PASSWORD', 'REDIS_PASSWORD']) assert.match(result.credentials.evidence?.join('\n') ?? '', new RegExp(name))
    assert.equal(JSON.stringify(result).includes('/must/not/be/opened'), false)
  } finally { removeFixture(root) }
})

test('does not follow links, open private-key stores, or read oversized and non-regular files', () => {
  const root = makeAppFixture()
  const outside = makeAppFixture()
  try {
    const key = path.join(outside, 'id_rsa')
    fs.writeFileSync(key, 'EXTERNAL_PRIVATE_MATERIAL_CANARY')
    fs.symlinkSync(key, path.join(root, '.env'))
    fs.linkSync(key, path.join(root, '.env.local'))
    fs.rmSync(path.join(root, '.env.example'))
    fs.linkSync(key, path.join(root, '.env.example'))
    assert.equal(readSafeText(root, '.env.example'), null)
    fs.writeFileSync(path.join(root, '.env.production'), 'x'.repeat(1_048_577))
    fs.mkdirSync(path.join(root, '.env.production.local'))
    const result = inspectLocalCredentials(root, true, {})
    assert.equal(result.credentials.status, 'warning')
    assert.equal(result.encryption.status, 'warning')
    assert.match(result.credentials.evidence?.join('\n') ?? '', /not inspected/)
    for (const value of ['EXTERNAL_PRIVATE_MATERIAL_CANARY', outside]) assert.equal(JSON.stringify(result).includes(value), false)
  } finally { removeFixture(root); removeFixture(outside) }
})

test('all report formats omit credential values, parser errors, and absolute paths', () => {
  const root = makeAppFixture()
  try {
    const canary = 'DO_NOT_LEAK_THIS_PRIVATE_SYNTHETIC_DEFAULT'
    fs.writeFileSync(path.join(root, '.env.production'), `JWT_SECRET=${canary}\nDATABASE_URL=postgres://app:${canary}@db/app\n`)
    fs.appendFileSync(path.join(root, '.env.example'), `\nJWT_SECRET=${canary}\n`)
    const report = scanTarget({ root, context: createScanContext(root, { checkSecrets: true, credentialEnvironment: {} }) }, new Date('2026-10-22T12:00:00Z'))
    assert.equal(report.schemaVersion, 1)
    assert.equal(report.results.find((rule) => rule.id === 'secrets-credential-strength')?.status, 'fail')
    for (const output of [formatJson(report), formatMarkdown(report), formatTerminal(report, false)]) for (const value of [canary, root]) assert.equal(output.includes(value), false)
  } finally { removeFixture(root) }
})

test('CLI checks credentials by default and accepts the old flag using only synthetic environment settings', () => {
  const root = makeAppFixture()
  try {
    fs.writeFileSync(path.join(root, '.env.production'), 'JWT_SECRET=changeme\nTENANT_DATA_ENCRYPTION_FALLBACK_KEY=om-dev-tenant-encryption\n')
    const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
    const run = (args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', path.join(repositoryRoot, 'src/cli.ts'), ...args], { cwd: repositoryRoot, encoding: 'utf8', env: { PATH: process.env.PATH ?? '' }, timeout: 30_000 })
    const checked = run(['scan', root, '--check-secrets', '--format', 'json', '--fail-on', 'critical'])
    assert.equal(checked.status, 1, checked.stderr)
    assert.equal(checked.stderr, '')
    assert.equal(JSON.parse(checked.stdout).results.find((rule: { id: string }) => rule.id === 'secrets-encryption-key-strength').status, 'fail')
    assert.equal(checked.stdout.includes('om-dev-tenant-encryption'), false)
    const ordinary = run(['scan', root, '--format', 'json', '--fail-on', 'critical'])
    assert.equal(ordinary.status, 1, ordinary.stderr)
    assert.equal(JSON.parse(ordinary.stdout).results.find((rule: { id: string }) => rule.id === 'secrets-credential-strength').status, 'fail')
    const apply = run(['apply', root, '--check-secrets', '--yes'])
    assert.equal(apply.status, 2)
    assert.match(apply.stderr, /apply never reads live credentials/)
  } finally { removeFixture(root) }
})


test('Compose credentials inherited from the runtime environment are assessed and absent ones need review', () => {
  const root = makeAppFixture()
  try {
    fs.writeFileSync(path.join(root, 'docker-compose.yml'), 'services:\n  db:\n    environment: [POSTGRES_PASSWORD]\n  app:\n    environment:\n      JWT_SECRET:\n')
    assert.equal(inspectLocalCredentials(root, true, { POSTGRES_PASSWORD: 'postgres', JWT_SECRET: 'secret' }).credentials.status, 'fail')
    const missing = inspectLocalCredentials(root, true, {})
    assert.equal(missing.credentials.status, 'warning')
    assert.match(missing.credentials.evidence?.join('\n') ?? '', /inherited/)
  } finally { removeFixture(root) }
})


test('programmatic scan contexts inspect credentials by default and permit apply to disable inspection', () => {
  const root = makeAppFixture()
  try {
    fs.writeFileSync(path.join(root, '.env.production'), 'JWT_SECRET=changeme\n')
    const enabled = createScanContext(root, { credentialEnvironment: {} })
    assert.equal(enabled.inspectCredentials().credentials.status, 'fail')
    const disabled = createScanContext(root, { checkSecrets: false, credentialEnvironment: {} })
    assert.equal(disabled.inspectCredentials().credentials.status, 'skipped')
  } finally { removeFixture(root) }
})
