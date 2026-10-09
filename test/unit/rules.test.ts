import assert from 'node:assert/strict'
import test from 'node:test'
import { RULES } from '../../src/rules.js'
import { SECURITY_RULES } from '../../src/security-rules.js'
import type { FindingStatus, ScanContext } from '../../src/types.js'
import { FILES, PRODUCTION_ENV } from '../fixture.js'

type Changes = {
  files?: Record<string, string | null>
  packageJson?: Record<string, unknown>
  trackedFiles?: ReadonlySet<string> | null
  environment?: Record<string, string>
}

function context(changes: Changes = {}): ScanContext {
  const files = { ...FILES, ...changes.files }
  return {
    root: '/unused-by-rules',
    environment: { values: new Map(Object.entries(changes.environment ?? PRODUCTION_ENV)), sources: ['test environment'], unreadableFiles: [] },
    inspectPermissions: () => ({ mode: 0o600, directory: false, symbolicLink: false }),
    inspectStoragePermissions: () => ({ inspected: 1, unsafe: 0, incomplete: false }),
    packageJson: changes.packageJson ?? JSON.parse(FILES['package.json'] ?? '{}') as Record<string, unknown>,
    trackedFiles: changes.trackedFiles === undefined ? new Set(Object.keys(FILES)) : changes.trackedFiles,
    exists: (file) => typeof files[file] === 'string',
    readText: (file) => files[file] ?? null,
    collectDeploymentText: () => Object.entries(files).filter(([file]) => !file.startsWith('.env') && !file.startsWith('.github')).map(([, text]) => text ?? '').join('\n'),
    collectCiText: () => Object.entries(files).filter(([file]) => file.startsWith('.github/workflows/')).map(([, text]) => text ?? '').join('\n'),
  }
}

const cases: { id: string; baseline: FindingStatus; changed: FindingStatus; changes: Changes }[] = [
  { id: 'secrets-live-env-untracked', baseline: 'pass', changed: 'fail', changes: { trackedFiles: new Set(['.env.production']) } },
  { id: 'secrets-no-tracked-credentials', baseline: 'pass', changed: 'fail', changes: { trackedFiles: new Set(['deploy.pem']) } },
  { id: 'secrets-ignore-policy', baseline: 'pass', changed: 'fail', changes: { files: { '.gitignore': 'node_modules/' } } },
  { id: 'runtime-env-template', baseline: 'pass', changed: 'fail', changes: { files: { '.env.example': 'NODE_ENV=production' } } },
  { id: 'runtime-production-scripts', baseline: 'pass', changed: 'fail', changes: { packageJson: { scripts: { build: 'next build', start: 'next start' } } } },
  { id: 'edge-tls-and-canonical-origin', baseline: 'warning', changed: 'fail', changes: { files: { 'docs/operations.md': '' } } },
  { id: 'edge-trusted-proxy-depth', baseline: 'warning', changed: 'fail', changes: { files: { '.env.example': 'RATE_LIMIT_TRUST_PROXY_DEPTH=-1' } } },
  { id: 'edge-allowed-origins', baseline: 'warning', changed: 'fail', changes: { files: { '.env.example': 'APP_ALLOWED_ORIGINS=' } } },
  { id: 'edge-security-headers', baseline: 'pass', changed: 'fail', changes: { files: { 'next.config.ts': 'export default {}' } } },
  { id: 'operations-health-check', baseline: 'warning', changed: 'fail', changes: { files: { 'railway.toml': '' } } },
  { id: 'infrastructure-private-services', baseline: 'pass', changed: 'fail', changes: { files: { 'docker-compose.yml': 'services:\n  postgres:\n    ports:\n      - "5432:5432"\n' } } },
  { id: 'container-non-root-user', baseline: 'pass', changed: 'fail', changes: { files: { Dockerfile: 'FROM node:24\nUSER app\nUSER root\n' } } },
  { id: 'supply-chain-immutable-install', baseline: 'pass', changed: 'fail', changes: { files: { Dockerfile: 'FROM node:24\nRUN yarn install\n' } } },
  { id: 'supply-chain-single-lockfile', baseline: 'pass', changed: 'fail', changes: { files: { 'package-lock.json': '{}' } } },
  { id: 'infrastructure-shared-redis', baseline: 'warning', changed: 'fail', changes: { files: { '.env.example': 'CACHE_STRATEGY=memory\nREDIS_URL=' } } },
  { id: 'release-database-migrations', baseline: 'warning', changed: 'fail', changes: { files: { 'railway.toml': '', 'docs/operations.md': '' } } },
  { id: 'release-immutable-artifact', baseline: 'warning', changed: 'fail', changes: { files: { 'docker-compose.fullapp.yml': 'services:\n  app:\n    image: app:latest' } } },
  { id: 'release-validation-gate', baseline: 'pass', changed: 'fail', changes: { files: { '.github/workflows/release.yml': 'steps:\n  - run: npm run build\n    continue-on-error: true' } } },
  { id: 'operations-worker-topology', baseline: 'pass', changed: 'fail', changes: { files: { 'railway.worker.toml': null, 'docker-compose.fullapp.yml': null } } },
  { id: 'workers-release-parity', baseline: 'pass', changed: 'fail', changes: { files: { 'railway.worker.toml': 'startCommand = "yarn mercato worker"\ndockerfilePath = "Dockerfile.worker"' } } },
  { id: 'storage-persistent-volume', baseline: 'warning', changed: 'fail', changes: { files: { 'docs/operations.md': '', 'docker-compose.fullapp.yml': '' } } },
  { id: 'data-backup-restore-runbook', baseline: 'warning', changed: 'fail', changes: { files: { 'docs/operations.md': 'Backups are configured.' } } },
  { id: 'release-rollback-runbook', baseline: 'warning', changed: 'fail', changes: { files: { 'docs/operations.md': '' } } },
  { id: 'observability-telemetry-pipeline', baseline: 'warning', changed: 'fail', changes: { files: { 'docker/otel-collector-config.yaml': null } } },
  { id: 'runtime-supported-node', baseline: 'pass', changed: 'fail', changes: { packageJson: { engines: { node: '>=20' } } } },
  { id: 'runtime-debug-features-disabled', baseline: 'warning', changed: 'fail', changes: { files: { '.env.example': 'NEXT_PUBLIC_UMES_DEVTOOLS=true' } } },
]

test('unit cases cover every stable rule ID exactly once', () => {
  assert.deepEqual(cases.map(({ id }) => id).sort(), RULES.filter(({ id }) => !SECURITY_RULES.some((rule) => rule.id === id)).map(({ id }) => id).sort())
})

for (const entry of cases) {
  test(`${entry.id}: baseline and unsafe or incomplete configuration`, () => {
    const rule = RULES.find(({ id }) => id === entry.id)
    assert.ok(rule)
    assert.equal(rule.check(context()).status, entry.baseline)
    const result = rule.check(context(entry.changes))
    assert.equal(result.status, entry.changed)
    assert.ok(result.summary.length > 0)
  })
}

test('secret checks request operator review when Git tracking is unavailable', () => {
  for (const id of ['secrets-live-env-untracked', 'secrets-no-tracked-credentials']) {
    assert.equal(RULES.find((rule) => rule.id === id)?.check(context({ trackedFiles: null })).status, 'warning')
  }
})

test('secret path evidence is deterministic regardless of tracking order', () => {
  const rule = RULES.find(({ id }) => id === 'secrets-live-env-untracked')
  assert.ok(rule)
  const first = rule.check(context({ trackedFiles: new Set(['.env.z', '.env.a']) }))
  const second = rule.check(context({ trackedFiles: new Set(['.env.a', '.env.z']) }))
  assert.deepEqual(first, second)
})

test('deployment evidence omits image values, port values, and absolute Dockerfile paths', () => {
  const marker = 'PRIVATE_VALUE_4151'
  const ctx = context({ files: {
    'docker-compose.fullapp.yml': `services:\n  postgres:\n    ports:\n      - "${marker}:5432"\n    image: ${marker}:latest\n`,
    'railway.toml': `dockerfilePath = "/home/${marker}/Dockerfile"`,
    'railway.worker.toml': 'dockerfilePath = "Dockerfile"',
  } })
  for (const rule of RULES) {
    const result = JSON.stringify(rule.check(ctx))
    assert.equal(result.includes(marker), false, rule.id)
    assert.equal(result.includes('/home/'), false, rule.id)
  }
})
