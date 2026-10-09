import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { makeAppFixture, removeFixture } from './fixture.js'

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const cli = path.join(repositoryRoot, 'src', 'cli.ts')

function run(args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', cli, ...args], {
    cwd: repositoryRoot,
    encoding: 'utf8',
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
    assert.match(result.stdout, /Open Mercato production readiness/)
    assert.match(fs.readFileSync(markdownPath, 'utf8'), /^# Open Mercato production readiness report/m)
    const report = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as { schemaVersion: number, results: unknown[] }
    assert.equal(report.schemaVersion, 1)
    assert.equal(report.results.length, 20)
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
    assert.match(saved.stdout, /^# Open Mercato production readiness report/m)
    assert.equal(fs.readFileSync(markdownPath, 'utf8'), saved.stdout)

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
