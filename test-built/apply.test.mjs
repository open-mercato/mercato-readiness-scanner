import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const cli = path.join(repositoryRoot, 'dist', 'cli.js')

const FILES = {
  'package.json': JSON.stringify({
    name: 'apply-fixture', private: true, engines: { node: '>=24' },
    dependencies: { '@open-mercato/core': '1.0.0' },
  }, null, 2),
  'src/modules.ts': 'export default []\n',
  '.gitignore': '.env\n',
  'yarn.lock': '# lock\n',
}

function insideWorktree(directory) {
  const result = spawnSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: directory, encoding: 'utf8' })
  return result.status === 0 && result.stdout.trim() === 'true'
}

/** TMPDIR can live inside a checkout, which would make the non-git case untestable. */
function nonRepositoryBase() {
  for (const candidate of [os.tmpdir(), '/tmp', path.join(os.homedir(), '.cache'), os.homedir()]) {
    if (!candidate || !fs.existsSync(candidate)) continue
    let probe
    try {
      probe = fs.mkdtempSync(path.join(candidate, 'mercato-readiness-probe-'))
    } catch {
      continue
    }
    let usable = !insideWorktree(probe)
    try {
      fs.writeFileSync(path.join(probe, 'probe'), 'probe')
    } catch {
      usable = false
    }
    fs.rmSync(probe, { recursive: true, force: true })
    if (usable) return candidate
  }
  throw new Error('no writable directory outside a git worktree is available')
}

function fixture(mode) {
  const base = mode === 'none' ? nonRepositoryBase() : os.tmpdir()
  const root = fs.mkdtempSync(path.join(base, 'mercato-readiness-apply-'))
  for (const [relativePath, contents] of Object.entries(FILES)) {
    const destination = path.join(root, relativePath)
    fs.mkdirSync(path.dirname(destination), { recursive: true })
    fs.writeFileSync(destination, contents)
  }
  if (mode === 'none') return root
  assert.equal(spawnSync('git', ['init', '--quiet'], { cwd: root }).status, 0)
  assert.equal(spawnSync('git', ['add', '.'], { cwd: root }).status, 0)
  assert.equal(spawnSync('git', ['-c', 'user.name=T', '-c', 'user.email=t@example.invalid', 'commit', '--quiet', '--no-gpg-sign', '-m', 'baseline'], { cwd: root }).status, 0)
  return root
}

function apply(args) {
  return spawnSync(process.execPath, [cli, 'apply', ...args], { cwd: repositoryRoot, encoding: 'utf8', timeout: 60_000 })
}

test('built CLI refuses to apply outside a git working tree', () => {
  const root = fixture('none')
  try {
    const result = apply([root, '--yes', '--no-color'])
    assert.equal(result.status, 2, result.stderr)
    assert.match(result.stderr, /is not a git working tree/)
    assert.equal(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), '.env\n')
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('built CLI never prompts on a non-TTY and applies safe policies with the explicit flag', () => {
  const root = fixture('commit')
  try {
    const refused = apply([root, '--no-color'])
    assert.equal(refused.signal, null, 'the built CLI must not hang waiting for an answer')
    assert.equal(refused.status, 2, refused.stderr)
    assert.match(refused.stderr, /stdin or stdout is not a TTY/)
    assert.equal(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), '.env\n')

    const applied = apply([root, '--yes', '--no-color'])
    assert.equal(applied.status, 0, applied.stderr)
    assert.match(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), /\.ai\/session-exports\//)
    assert.ok(fs.existsSync(path.join(root, 'docs/runbooks/backup-and-restore.md')))

    const again = apply([root, '--yes', '--allow-dirty', '--no-color'])
    assert.equal(again.status, 0, again.stderr)
    assert.match(again.stdout, /0 change\(s\) written/)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('built CLI prints an inspectable cezar-run prompt without spawning anything', () => {
  const root = fixture('commit')
  try {
    const result = apply([root, '--mode', 'agent', '--print-prompt', '--no-color'])
    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, /^# Task: apply Open Mercato production-readiness remediations$/m)
    assert.match(result.stdout, /## Readiness report \(inlined\)/)
    assert.match(result.stdout, /## Definition of done/)
    assert.equal(fs.existsSync(path.join(root, 'docs/runbooks')), false)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})
