import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { collectCiText, existsInside, isLiveEnvPath, readSafeText } from '../../src/files.js'

test('generic configuration reads block live dotenv and secret stores before opening contents', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'readiness-deny-'))
  const names = ['.env', '.env.production', '.envrc', 'nested/.ENV.local', '.npmrc', 'id_rsa', 'private.key', 'credentials.json', '.aws/config', '.config/gcloud/access_tokens.db', 'secrets/settings.md', '.git/config']
  try {
    for (const file of names) {
      fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true })
      fs.writeFileSync(path.join(root, file), 'SYNTHETIC_MATERIAL_MUST_NOT_BE_OPENED')
    }
    const open = t.mock.method(fs, 'openSync', () => { throw new Error('Forbidden read') })
    for (const file of names) assert.equal(readSafeText(root, file), null, file)
    assert.equal(open.mock.callCount(), 0)
    open.mock.restore()
    for (const file of ['.env', '.envrc', 'nested/.env.production']) assert.equal(isLiveEnvPath(file), true)
    for (const file of ['.env.example', '.env.sample', '.env.template', 'docs/config.md']) assert.equal(isLiveEnvPath(file), false)
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
})

test('rejects traversal, symlinks, directories, and oversized text', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'readiness-files-'))
  try {
    fs.writeFileSync(path.join(root, 'safe.txt'), 'safe')
    fs.writeFileSync(path.join(root, '.env.example'), 'APP_URL=')
    fs.writeFileSync(path.join(root, 'large.txt'), 'a'.repeat(1_048_577))
    fs.symlinkSync(path.join(root, 'safe.txt'), path.join(root, 'linked.txt'))
    assert.equal(readSafeText(root, 'safe.txt'), 'safe')
    assert.equal(readSafeText(root, '.env.example'), 'APP_URL=')
    assert.equal(readSafeText(root, '../safe.txt'), null)
    assert.equal(readSafeText(root, path.join(root, 'safe.txt')), null)
    assert.equal(readSafeText(root, '.'), null)
    assert.equal(readSafeText(root, 'large.txt'), null)
    assert.equal(readSafeText(root, 'linked.txt'), null)
    assert.equal(existsInside(root, '../safe.txt'), false)
    assert.equal(existsInside(root, 'linked.txt'), false)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('collects workflow text in a stable order and excludes secret directories', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'readiness-ci-'))
  const workflows = path.join(root, '.github/workflows')
  try {
    fs.mkdirSync(path.join(workflows, 'secrets'), { recursive: true })
    fs.writeFileSync(path.join(workflows, 'z.yml'), 'last')
    fs.writeFileSync(path.join(workflows, 'a.yml'), 'first')
    fs.writeFileSync(path.join(workflows, 'secrets', 'values.yml'), 'MUST_NOT_READ')
    assert.equal(collectCiText(root), 'first\nlast')
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})
