import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { readSafeText } from '../src/files.js'
import { formatJson, formatMarkdown, formatTerminal } from '../src/formatters.js'
import { RULES } from '../src/rules.js'
import { scan } from '../src/scan.js'
import { makeAppFixture, PRODUCTION_ENV, removeFixture } from './fixture.js'
import { assertReport } from './report-contract.js'

test('scans a generated application and returns one result per documented rule', () => {
  const root = makeAppFixture()
  try {
    const report = scan(path.join(root, 'src'), new Date('2026-10-09T12:00:00.000Z'))
    assertReport(report)
    assert.equal(report.schemaVersion, 1)
    assert.equal(report.target, path.basename(root))
    assert.equal(report.summary.total, RULES.length)
    assert.equal(report.results.length, RULES.length)
    assert.equal(report.summary.total, report.summary.pass + report.summary.fail + report.summary.warning + report.summary.skipped)
    assert.equal(new Set(report.results.map((result) => result.id)).size, RULES.length)
    assert.equal(new Set(report.results.map((result) => result.docsUrl)).size, RULES.length)
  } finally {
    removeFixture(root)
  }
})

test('inspects authorized production configuration without exposing tracked secret values', () => {
  const root = makeAppFixture()
  const secret = 'SHOULD_NOT_APPEAR_7d51f9'
  try {
    fs.writeFileSync(path.join(root, '.env.production'), `DATABASE_URL=${secret}\n`)
    fs.writeFileSync(path.join(root, '.env-prod'), `DATABASE_URL=${secret}\n`)
    fs.writeFileSync(path.join(root, '.envrc'), `export DATABASE_URL=${secret}\n`)
    assert.equal(readSafeText(root, '.env.production'), null)
    assert.equal(readSafeText(root, '.env.local'), null)
    const added = spawnSync('git', ['add', '--force', '.env.production', '.env-prod', '.envrc'], { cwd: root }).status
    assert.equal(added, 0)
    const report = scan(root)
    const finding = report.results.find((result) => result.id === 'secrets-live-env-untracked')
    assert.equal(finding?.status, 'fail')
    assert.deepEqual(finding?.evidence, ['Tracked sensitive path: .env-prod', 'Tracked sensitive path: .env.production', 'Tracked sensitive path: .envrc'])
    assert.equal(JSON.stringify(report).includes(secret), false)
  } finally {
    removeFixture(root)
  }
})

test('detects credential-like tracked paths without opening their contents', () => {
  const root = makeAppFixture()
  const secret = 'PRIVATE_MATERIAL_SHOULD_NOT_APPEAR_186b0e'
  try {
    fs.writeFileSync(path.join(root, 'deployment.pem'), secret)
    fs.writeFileSync(path.join(root, 'id_ecdsa'), secret)
    fs.mkdirSync(path.join(root, '.aws'), { recursive: true })
    fs.writeFileSync(path.join(root, '.aws', 'credentials'), secret)
    assert.equal(readSafeText(root, 'deployment.pem'), null)
    assert.equal(readSafeText(root, 'id_ecdsa'), null)
    assert.equal(readSafeText(root, '.aws/credentials'), null)
    assert.equal(spawnSync('git', ['add', '--force', 'deployment.pem', 'id_ecdsa', '.aws/credentials'], { cwd: root }).status, 0)
    const report = scan(root)
    const finding = report.results.find((result) => result.id === 'secrets-no-tracked-credentials')
    assert.equal(finding?.status, 'fail')
    assert.deepEqual(finding?.evidence, ['Tracked sensitive path: .aws/credentials', 'Tracked sensitive path: deployment.pem', 'Tracked sensitive path: id_ecdsa'])
    assert.equal(JSON.stringify(report).includes(secret), false)
  } finally {
    removeFixture(root)
  }
})

test('does not follow symlinks outside the scanned application', () => {
  const root = makeAppFixture()
  const outside = fs.mkdtempSync(path.join(path.dirname(root), 'mercato-readiness-outside-'))
  try {
    fs.writeFileSync(path.join(outside, 'runbook.md'), 'OUTSIDE_CONTENT_SHOULD_NOT_BE_READ')
    fs.symlinkSync(outside, path.join(root, 'linked-docs'))
    assert.equal(readSafeText(root, 'linked-docs/runbook.md'), null)
  } finally {
    removeFixture(root)
    removeFixture(outside)
  }
})

test('renders polished terminal, Markdown, and machine-readable JSON reports', () => {
  const root = makeAppFixture()
  try {
    fs.rmSync(path.join(root, 'Dockerfile'))
    const report = scan(root, new Date('2026-10-09T12:00:00.000Z'))
    const terminal = formatTerminal(report, false)
    const markdown = formatMarkdown(report)
    const json = formatJson(report)
    assert.match(terminal, /Open Mercato production readiness/)
    assert.match(terminal, /✅/)
    assert.match(terminal, /⚠️/)
    assert.match(terminal, /⏭️/)
    assert.match(markdown, /^# Open Mercato production readiness report/m)
    assert.match(markdown, /\[edge-tls-and-canonical-origin\]\(https:\/\/github\.com\/open-mercato\/mercato-readiness-scanner\/blob\/main\/docs\/rules\/edge-tls-and-canonical-origin\.md\)/)
    assert.deepEqual(JSON.parse(json), report)
  } finally {
    removeFixture(root)
  }
})

test('every rule has a matching standalone documentation page', () => {
  const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  for (const rule of RULES) {
    const documentation = path.join(repositoryRoot, 'docs', 'rules', `${rule.id}.md`)
    assert.equal(fs.existsSync(documentation), true, `missing ${documentation}`)
    const source = fs.readFileSync(documentation, 'utf8')
    assert.equal(source.includes(`**Rule ID:** \`${rule.id}\``), true)
    assert.match(source, /## Remediation/)
  }
})

test('checks dotenv and inherited deployment settings, redacts all formats, and never runs target scripts', () => {
  const root = makeAppFixture()
  const marker = 'PRIVATE_SECRET_MARKER_83a918bbea91ab3'
  try {
    const env = Object.entries(PRODUCTION_ENV).map(([key, value]) => `${key}=${value}`).join('\n')
    fs.writeFileSync(path.join(root, '.env.production'), `${env}\nJWT_SECRET=${marker}\n`, { mode: 0o600 })
    fs.mkdirSync(path.join(root, 'uploads'), { mode: 0o700 })
    fs.writeFileSync(path.join(root, 'uploads', 'private.txt'), 'PRIVATE_UPLOAD_CONTENT', { mode: 0o600 })
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as Record<string, unknown>
    manifest.scripts = { build: 'touch TARGET_SCRIPT_EXECUTED', start: 'touch TARGET_SCRIPT_EXECUTED' }
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest))
    const report = scan(root, { environment: {} })
    for (const id of ['secrets-jwt-signing', 'data-tenant-encryption-enabled', 'data-encryption-key-config', 'services-postgres-credentials', 'services-redis-credentials', 'runtime-production-environment', 'runtime-tracing-disabled', 'permissions-env-files', 'permissions-upload-directories']) {
      assert.equal(report.results.find((rule) => rule.id === id)?.status, 'pass', id)
    }
    const override = scan(root, { environment: { JWT_SECRET: 'weak', TENANT_DATA_ENCRYPTION: 'no' } })
    assert.equal(override.results.find(({ id }) => id === 'secrets-jwt-signing')?.status, 'fail')
    assert.equal(override.results.find(({ id }) => id === 'data-tenant-encryption-enabled')?.status, 'fail')
    for (const output of [formatJson(report), formatMarkdown(report), formatTerminal(report, false)]) {
      assert.equal(output.includes(marker), false)
      assert.equal(output.includes('PRIVATE_UPLOAD_CONTENT'), false)
      assert.equal(output.includes(root), false)
      for (const value of Object.values(PRODUCTION_ENV).filter((value) => value.length > 25)) assert.equal(output.includes(value), false)
    }
    assert.equal(fs.existsSync(path.join(root, 'TARGET_SCRIPT_EXECUTED')), false)
    fs.chmodSync(path.join(root, 'uploads', 'private.txt'), 0o666)
    fs.chmodSync(path.join(root, '.env.production'), 0o644)
    const permissions = scan(root, { environment: {} })
    assert.equal(permissions.results.find(({ id }) => id === 'permissions-upload-directories')?.status, 'fail')
    assert.equal(permissions.results.find(({ id }) => id === 'permissions-env-files')?.status, 'fail')
  } finally { removeFixture(root) }
})
