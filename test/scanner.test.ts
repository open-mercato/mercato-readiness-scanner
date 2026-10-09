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
import { makeAppFixture, removeFixture } from './fixture.js'

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
    assert.equal(readSafeText(root, '.env.production'), null)
    assert.equal(readSafeText(root, '.env.local'), null)
    const added = spawnSync('git', ['add', '--force', '.env.production'], { cwd: root }).status
    assert.equal(added, 0)
    const report = scan(root)
    const finding = report.results.find((result) => result.id === 'secrets-live-env-untracked')
    assert.equal(finding?.status, 'fail')
    assert.deepEqual(finding?.evidence, ['Tracked sensitive path: .env.production'])
    assert.equal(JSON.stringify(report).includes(secret), false)
  } finally {
    removeFixture(root)
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
