import fs from 'node:fs'
import { spawnSync } from 'node:child_process'

const built = process.argv[2] === 'built'
const directory = built ? 'test-built' : 'test'
const extension = built ? '.test.mjs' : '.test.ts'
const files = fs.readdirSync(directory).filter((file) => file.endsWith(extension)).sort().map((file) => `${directory}/${file}`)
// Default scans inspect their environment. Tests must see synthetic credentials only.
const environment = {}
for (const name of ['PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'SystemRoot', 'SYSTEMROOT', 'COMSPEC', 'PATHEXT', 'USERPROFILE']) {
  if (process.env[name] !== undefined) environment[name] = process.env[name]
}
const result = spawnSync(process.execPath, [...(built ? [] : ['--import', 'tsx']), '--test', ...files], {
  stdio: 'inherit', env: environment,
})
if (result.error) throw result.error
process.exitCode = result.status ?? 3
