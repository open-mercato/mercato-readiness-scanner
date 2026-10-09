import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { RULES } from '../src/rules.js'
import { makeAppFixture, removeFixture } from './fixture.js'

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const cli = path.join(repositoryRoot, 'src', 'cli.ts')

function run(args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', cli, ...args], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: Object.fromEntries(Object.entries(process.env).filter(([key]) => ['PATH', 'SYSTEMROOT', 'TMPDIR', 'TEMP', 'TMP', 'HOME'].includes(key))),
  })
}

test('keeps terminal output while saving Markdown and JSON reports', () => {
  const root = makeAppFixture()
  const output = path.join(root, 'reports')
  const markdownPath = path.join(output, 'readiness.md')
  const jsonPath = path.join(output, 'readiness.json')
  try {
    const result = run(['scan', root, '--no-color', '--markdown', markdownPath, '--json', jsonPath])
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stderr, '')
    assert.match(result.stdout, /Open Mercato production readiness/)
    assert.match(fs.readFileSync(markdownPath, 'utf8'), /^# Open Mercato production readiness report/m)
    const report = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as { schemaVersion: number, results: unknown[] }
    assert.equal(report.schemaVersion, 1)
    assert.equal(report.results.length, RULES.length)
    if (process.platform !== 'win32') {
      assert.equal(fs.statSync(markdownPath).mode & 0o777, 0o600)
      assert.equal(fs.statSync(jsonPath).mode & 0o777, 0o600)
    }
  } finally {
    removeFixture(root)
  }
})

test('infers the saved format and supports severity exit thresholds', () => {
  const root = makeAppFixture()
  const markdownPath = path.join(root, 'single.md')
  try {
    const saved = run([root, '--output', markdownPath])
    assert.equal(saved.status, 0, saved.stderr)
    assert.equal(saved.stdout, '')
    assert.match(fs.readFileSync(markdownPath, 'utf8'), /^# Open Mercato production readiness report/m)

    const stdout = run([root, '--format', 'json', '--output', '-'])
    assert.equal(stdout.status, 0, stdout.stderr)
    assert.equal((JSON.parse(stdout.stdout) as { schemaVersion: number }).schemaVersion, 1)

    fs.rmSync(path.join(root, 'docs'), { recursive: true })
    const failing = run([root, '--fail-on', 'critical', '--no-color'])
    assert.equal(failing.status, 1)
    assert.match(failing.stdout, /❌/)
  } finally {
    removeFixture(root)
  }
})

test('returns usage error for a directory that is not an Open Mercato app', () => {
  const empty = fs.mkdtempSync(path.join(repositoryRoot, '.tmp-invalid-'))
  try {
    const result = run([empty])
    assert.equal(result.status, 2)
    assert.match(result.stderr, /No create-mercato-app application was found/)
  } finally {
    fs.rmSync(empty, { recursive: true, force: true })
  }
})

test('help works outside an app and diagnostics use distinct exit codes', () => {
  const help = run(['--help'])
  assert.equal(help.status, 0)
  assert.match(help.stdout, /Usage:/)
  assert.equal(help.stderr, '')

  const invalidOption = run(['--unknown'])
  assert.equal(invalidOption.status, 2)
  assert.equal(invalidOption.stdout, '')
  assert.match(invalidOption.stderr, /Unknown option/)

  const root = makeAppFixture()
  try {
    const outputFailure = run([root, '--output', root])
    assert.equal(outputFailure.status, 3)
    assert.equal(outputFailure.stdout, '')
    assert.match(outputFailure.stderr, /mercato-readiness:/)
  } finally {
    removeFixture(root)
  }
})

test('lists rule IDs and applies repeatable only/ignore selection before failure thresholds', () => {
  const listing = run(['--list-rules'])
  assert.equal(listing.status, 0)
  for (const rule of RULES) assert.ok(listing.stdout.includes(`${rule.id}\t`))
  const root = makeAppFixture()
  try {
    const selected = run([root, '--only', 'secrets-jwt-signing,data-tenant-encryption-enabled', '--ignore', 'secrets-jwt-signing', '--ignore', 'data-tenant-encryption-enabled', '--fail-on', 'low', '--format', 'json'])
    assert.equal(selected.status, 0, selected.stderr)
    const report = JSON.parse(selected.stdout) as { results: { status: string }[] }
    assert.ok(report.results.every(({ status }) => status === 'skipped'))
    const failing = run([root, '--only', 'secrets-jwt-signing', '--fail-on', 'critical', '--format', 'json'])
    assert.equal(failing.status, 1)
    const unknown = run([root, '--ignore', 'secrets-jwt-singing'])
    assert.equal(unknown.status, 2)
    assert.match(unknown.stderr, /Unknown rule ID/)
    const empty = run([root, '--only', ','])
    assert.equal(empty.status, 2)
  } finally { removeFixture(root) }
})
