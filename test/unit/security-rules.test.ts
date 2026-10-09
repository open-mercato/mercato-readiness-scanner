import assert from 'node:assert/strict'
import test from 'node:test'
import { SECURITY_RULES } from '../../src/security-rules.js'
import { RULES } from '../../src/rules.js'
import type { ScanContext } from '../../src/types.js'
import { PRODUCTION_ENV } from '../fixture.js'

function context(overrides: Record<string, string> = {}): ScanContext {
  return {
    root: '/unused', packageJson: {}, trackedFiles: new Set(),
    environment: { values: new Map(Object.entries({ ...PRODUCTION_ENV, ...overrides })), sources: ['process environment'], unreadableFiles: [] },
    exists: () => false, readText: () => null, collectCiText: () => '', collectDeploymentText: () => '',
    inspectPermissions: () => ({ mode: 0o600, directory: false, symbolicLink: false }),
    inspectStoragePermissions: () => ({ inspected: 2, unsafe: 0, incomplete: false }),
  }
}
const cases: { id: string; overrides: Record<string, string> }[] = [
  { id: 'secrets-jwt-signing', overrides: { JWT_SECRET: 'change-me-dev-secret' } },
  { id: 'data-tenant-encryption-enabled', overrides: { TENANT_DATA_ENCRYPTION: 'no' } },
  { id: 'data-encryption-key-config', overrides: { TENANT_DATA_ENCRYPTION_FALLBACK_KEY: PRODUCTION_ENV.JWT_SECRET ?? '' } },
  { id: 'services-postgres-credentials', overrides: { DATABASE_URL: 'postgresql://postgres:postgres@db/app' } },
  { id: 'services-redis-credentials', overrides: { REDIS_URL: 'redis://cache:6379' } },
  { id: 'services-other-credentials', overrides: { MEILISEARCH_URL: 'https://search.test.invalid', MEILISEARCH_API_KEY: 'meilisearch-dev-key' } },
  { id: 'runtime-production-environment', overrides: { NODE_ENV: 'development', APP_URL: 'http://localhost:3000' } },
  { id: 'runtime-tracing-disabled', overrides: { TELEMETRY_BACKEND: 'otlp', QUERY_ENGINE_DEBUG_SQL: 'true' } },
]

test('every rule has unit coverage in the repository or environment suites', () => {
  assert.equal(RULES.length, 26 + SECURITY_RULES.length)
  assert.deepEqual([...cases.map(({ id }) => id), 'permissions-env-files', 'permissions-upload-directories'].sort(), SECURITY_RULES.map(({ id }) => id).sort())
})
for (const { id, overrides } of cases) {
  test(`${id}: accepts production configuration and rejects unsafe settings without echoing values`, () => {
    const rule = SECURITY_RULES.find((rule) => rule.id === id)
    assert.ok(rule)
    assert.equal(rule.check(context()).status, 'pass')
    const outcome = rule.check(context(overrides))
    assert.equal(outcome.status, 'fail')
    for (const [name, value] of Object.entries(overrides)) {
      if (name !== 'NODE_ENV' && value.length > 10) assert.equal(JSON.stringify(outcome).includes(value), false)
    }
  })
}

test('optional JWT overrides, Redis roles, and supporting service credentials are checked', () => {
  for (const [id, settings] of [
    ['secrets-jwt-signing', { DOCUMENTS_COLLAB_JWT_SECRET_V2: 'weak' }],
    ['services-redis-credentials', { CACHE_REDIS_URL: 'redis://cache:6379' }],
    ['services-other-credentials', { AWS_ACCESS_KEY_ID: 'synthetic-id', AWS_SECRET_ACCESS_KEY: '' }],
    ['services-other-credentials', { MEILISEARCH_HOST: 'https://search.test.invalid' }],
    ['services-other-credentials', { OM_INTEGRATION_STORAGE_S3_ACCESS_KEY_ID: 'synthetic-id' }],
    ['services-other-credentials', { VAULT_ADDR: 'https://vault.test.invalid' }],
    ['services-other-credentials', { SMTP_USER: 'mailer', SMTP_PASSWORD: 'password' }],
    ['services-other-credentials', { RABBITMQ_URL: 'amqp://guest:guest@queue' }],
  ] as const) {
    assert.equal(SECURITY_RULES.find((rule) => rule.id === id)?.check(context(settings)).status, 'fail', id)
  }
})

test('environment file permissions reject group/world access', () => {
  const rule = SECURITY_RULES.find(({ id }) => id === 'permissions-env-files')
  assert.ok(rule)
  assert.equal(rule.check(context()).status, 'pass')
  const ctx = context()
  ctx.inspectPermissions = () => ({ mode: 0o644, directory: false, symbolicLink: false })
  assert.equal(rule.check(ctx).status, 'fail')
  ctx.inspectPermissions = () => null
  assert.equal(rule.check(ctx).status, 'skipped')
})

test('upload permissions fail unsafe metadata and require review for incomplete traversal', () => {
  const rule = SECURITY_RULES.find(({ id }) => id === 'permissions-upload-directories')
  assert.ok(rule)
  const ctx = context({ UPLOADS_DIR: '/home/private-mount' })
  assert.equal(rule.check(ctx).status, 'pass')
  ctx.inspectStoragePermissions = () => ({ inspected: 2, unsafe: 1, incomplete: false })
  const failed = rule.check(ctx)
  assert.equal(failed.status, 'fail')
  assert.equal(JSON.stringify(failed).includes('/home/'), false)
  ctx.inspectStoragePermissions = () => ({ inspected: 2, unsafe: 0, incomplete: true })
  assert.equal(rule.check(ctx).status, 'warning')
})
