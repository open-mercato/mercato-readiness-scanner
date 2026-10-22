import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { RULES } from '../src/rules.js'
import { makeAppFixture, makeMonorepoFixture, removeFixture } from './fixture.js'

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const cli = path.join(repositoryRoot, 'src', 'cli.ts')

function run(args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', cli, ...args], {
    cwd: repositoryRoot,
    encoding: 'utf8',
  })
}

test('always rejects monorepo targets before rendering or saving reports', () => {
  const root = makeMonorepoFixture()
  try {
    for (const format of ['terminal', 'markdown', 'json']) {
      const result = run(['scan', path.join(root, 'apps/mercato/src'), '--format', format, '--fail-on', 'never'])
      assert.equal(result.status, 2)
      assert.equal(result.stdout, '')
      assert.match(result.stderr, /\[runtime-standalone-application\]/)
      assert.match(result.stderr, /monorepo is not a valid way to start a production app/)
      assert.match(result.stderr, /create-mercato-app/)
      assert.equal(result.stderr.includes(root), false)
    }
    const output = path.join(root, 'reports')
    const saved = run([root, '--output', path.join(output, 'primary.md'),
      '--markdown', path.join(output, 'readiness.md'), '--json', path.join(output, 'readiness.json')])
    assert.equal(saved.status, 2)
    assert.equal(saved.stdout, '')
    assert.match(saved.stderr, /create-mercato-app/)
    assert.equal(fs.existsSync(output), false)
  } finally {
    removeFixture(root)
  }
})

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
