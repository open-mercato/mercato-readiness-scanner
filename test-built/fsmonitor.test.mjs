import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const cli = path.join(repositoryRoot, 'dist', 'cli.js')

test('built CLI disables repository-controlled fsmonitor execution', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mercato-readiness-fsmonitor-'))
  const marker = path.join(root, 'fsmonitor-ran')
  const hook = path.join(root, 'repo-controlled-fsmonitor.sh')
  try {
    fs.mkdirSync(path.join(root, 'src'), { recursive: true })
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ dependencies: { '@open-mercato/core': '1.0.0' } }))
    fs.writeFileSync(path.join(root, 'src', 'modules.ts'), 'export default []\n')
    fs.writeFileSync(hook, `#!/bin/sh\nprintf executed > ${JSON.stringify(marker)}\nprintf '0\\n'\n`)
    fs.chmodSync(hook, 0o755)
    assert.equal(spawnSync('git', ['init', '--quiet'], { cwd: root }).status, 0)
    assert.equal(spawnSync('git', ['add', '.'], { cwd: root }).status, 0)
    assert.equal(spawnSync('git', ['config', 'core.fsmonitor', './repo-controlled-fsmonitor.sh'], { cwd: root }).status, 0)

    const result = spawnSync(process.execPath, [cli, root, '--format', 'json'], { cwd: repositoryRoot, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    assert.equal((JSON.parse(result.stdout)).schemaVersion, 1)
    assert.equal(fs.existsSync(marker), false)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})
