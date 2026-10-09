import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { assertReport } from '../report-contract.js'

const repository = fileURLToPath(new URL('../../', import.meta.url))
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const version = process.env.MERCATO_APP_VERSION ?? '0.8.0'
if (!/^[\w.+-]+$/.test(version)) throw new Error('MERCATO_APP_VERSION must be a registry version or tag')

function run(command: string, args: string[], cwd: string): string {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 4 * 1_048_576,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, CI: 'true', NO_COLOR: '1' },
  })
  assert.equal(result.error, undefined, result.error?.message ?? 'Command failed to start')
  assert.equal(result.status, 0, `${command} failed:\n${result.stderr}\n${result.stdout}`)
  return result.stdout
}

// Compare metadata without opening any application file or secret store.
function inventory(root: string): Record<string, { size: number; mtime: number; mode: number }> {
  const files: Record<string, { size: number; mtime: number; mode: number }> = {}
  const visit = (relative: string): void => {
    for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true })) {
      if (entry.name === '.git') continue
      const file = path.join(relative, entry.name)
      const stat = fs.lstatSync(path.join(root, file))
      files[file] = { size: stat.size, mtime: stat.mtimeMs, mode: stat.mode }
      if (entry.isDirectory()) visit(file)
    }
  }
  visit('')
  return files
}

test('packed npm CLI scans a fresh standalone Open Mercato app and saves valid security reports', { timeout: 600_000 }, () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'readiness-standalone-'))
  const app = path.join(workspace, 'standalone-app')
  const consumer = path.join(workspace, 'consumer')
  const reports = path.join(repository, 'reports', `standalone-${version}`)
  try {
    run(npm, ['exec', '--yes', '--ignore-scripts', `--package=create-mercato-app@${version}`, '--',
      'create-mercato-app', 'standalone-app', '--preset', 'empty', '--agents', 'none', '--no-init-git'], workspace)
    assert.equal(fs.existsSync(path.join(app, 'src/modules.ts')), true)
    assert.equal(fs.existsSync(path.join(app, 'node_modules')), false, 'The app must remain uninstalled')
    run('git', ['init', '--quiet'], app)
    run('git', ['add', '--', 'package.json', 'src/modules.ts', '.gitignore', '.env.example'], app)

    const packed: unknown = JSON.parse(run(npm, ['pack', '--ignore-scripts', '--json', '--pack-destination', workspace], repository))
    assert.ok(Array.isArray(packed))
    const filename = (packed[0] as { filename: string }).filename
    assert.equal(path.basename(filename), filename)
    fs.mkdirSync(consumer)
    fs.writeFileSync(path.join(consumer, 'package.json'), '{"name":"scanner-consumer","private":true,"type":"module"}')
    run(npm, ['install', '--ignore-scripts', '--no-audit', '--no-fund', path.join(workspace, filename)], consumer)
    const installed = path.join(consumer, 'node_modules/@open-mercato/readiness-scanner')
    assert.equal(fs.existsSync(path.join(installed, 'src')), false)
    assert.equal(fs.existsSync(path.join(installed, 'node_modules')), false, 'CLI must need no runtime dependencies')
    const manifest = JSON.parse(fs.readFileSync(path.join(installed, 'package.json'), 'utf8')) as { version: string }
    const cliVersion = run(npm, ['exec', '--offline', '--', 'mercato-readiness', '--version'], consumer).trim()
    assert.equal(cliVersion, manifest.version)
    // This import runs in a consumer without TypeScript or tsx installed.
    run(process.execPath, ['--input-type=module', '-e', 'import { scan } from "@open-mercato/readiness-scanner"; if (typeof scan !== "function") process.exit(1)'], consumer)

    fs.mkdirSync(reports, { recursive: true })
    const before = inventory(app)
    const terminal = run(npm, ['exec', '--offline', '--', 'mercato-readiness', 'scan', path.join(app, 'src'),
      '--no-color', '--fail-on', 'never', '--markdown', path.join(reports, 'security.md'), '--json', path.join(reports, 'security.json')], consumer)
    assert.match(terminal, /Open Mercato production readiness/)
    assert.deepEqual(inventory(app), before, 'Scanning must not mutate the target application')
    const report: unknown = JSON.parse(fs.readFileSync(path.join(reports, 'security.json'), 'utf8'))
    assertReport(report)
    assert.equal(report.target, 'standalone-app')
    assert.ok(report.results.some(({ category }) => category === 'Secrets'))
    assert.ok(report.results.some(({ severity }) => severity === 'critical'))
    assert.match(fs.readFileSync(path.join(reports, 'security.md'), 'utf8'), /^# Open Mercato production readiness report/m)
    assert.equal(JSON.stringify(report).includes(workspace), false)
    const second: unknown = JSON.parse(run(npm, ['exec', '--offline', '--', 'mercato-readiness', 'scan', app, '--format', 'json'], consumer))
    assertReport(second)
    assert.deepEqual(second.results, report.results)
    assert.deepEqual(second.summary, report.summary)
    // Reports stay in the job workspace; no target files or scan results are uploaded.
    process.stdout.write(`Generated reports: reports/standalone-${version}/security.{md,json}\n`)
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true })
  }
})
