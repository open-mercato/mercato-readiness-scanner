import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { readSafeText } from '../src/files.js'
import { formatJson, formatMarkdown, formatTerminal } from '../src/formatters.js'
import { RULES } from '../src/rules.js'
import { InvalidTargetError, scan } from '../src/scan.js'
import { makeAppFixture, makeMonorepoFixture, removeFixture } from './fixture.js'

test('rejects the framework monorepo from the root, internal app, packages, and template', () => {
  const root = makeMonorepoFixture()
  try {
    for (const relativePath of ['', 'apps/mercato', 'apps/mercato/src', 'apps/mercato/src/modules.ts', 'packages/core', 'packages/create-app/template/src']) {
      assert.throws(() => scan(path.join(root, relativePath)), (error: unknown) => {
        assert.ok(error instanceof InvalidTargetError)
        assert.match(error.message, /\[runtime-standalone-application\]/)
        assert.match(error.message, /monorepo is not a valid way to start a production app/)
        assert.match(error.message, /create-mercato-app/)
        assert.equal(error.message.includes(root), false)
        return true
      })
    }
    // A root that also matches generated-app markers must still be rejected.
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))
    manifest.dependencies = { '@open-mercato/core': 'workspace:*' }
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest))
    fs.mkdirSync(path.join(root, 'src'))
    fs.writeFileSync(path.join(root, 'src/modules.ts'), 'export default []\n')
    assert.throws(() => scan(root), /monorepo is not a valid way to start a production app/)
  } finally {
    removeFixture(root)
  }
})

test('recognizes a renamed framework package with object-form workspaces', () => {
  const root = makeMonorepoFixture()
  try {
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      name: 'renamed-framework', workspaces: { packages: ['apps/*', 'packages/*'] },
    }))
    assert.throws(() => scan(path.join(root, 'apps/mercato/src')), /create-mercato-app/)
  } finally {
    removeFixture(root)
  }
})

test('supports generated apps in unrelated workspaces without following external package markers', () => {
  const root = makeAppFixture()
  const outside = makeMonorepoFixture()
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))
    manifest.name = 'open-mercato'
    manifest.workspaces = ['packages/*']
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest))
    assert.equal(scan(root).results.length, RULES.length)
    fs.symlinkSync(path.join(outside, 'packages'), path.join(root, 'packages'))
    assert.equal(scan(root).results.length, RULES.length)
  } finally {
    removeFixture(root)
    removeFixture(outside)
  }
})

test('scans a generated application and returns one result per documented rule', () => {
  const root = makeAppFixture()
  try {
    const report = scan(path.join(root, 'src'), new Date('2026-10-09T12:00:00.000Z'))
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

test('never reads a tracked live environment file or exposes its value', () => {
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
