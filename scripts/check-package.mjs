import { spawnSync } from 'node:child_process'

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const packed = spawnSync(npmCommand, ['pack', '--dry-run', '--json'], {
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'inherit'],
})

if (packed.error || packed.status !== 0) {
  throw packed.error ?? new Error(`npm pack exited with ${packed.status}`)
}

const reports = JSON.parse(packed.stdout)
const report = Array.isArray(reports) ? reports[0] : null
if (!report || !Array.isArray(report.files)) throw new Error('npm pack did not return a file inventory')

const files = new Map(report.files.map((entry) => [entry.path, entry]))
if (report.name !== 'mercato-readiness-scanner') throw new Error('packed package has an unexpected name')
for (const required of ['package.json', 'README.md', 'dist/cli.js', 'docs/report.schema.json']) {
  if (!files.has(required)) throw new Error(`packed package is missing ${required}`)
}
for (const forbidden of ['src/', 'test/', 'test-built/', 'scripts/', '.ai/', '.git/', 'node_modules/']) {
  if ([...files.keys()].some((entry) => entry.startsWith(forbidden))) throw new Error(`packed package contains ${forbidden}`)
}
if (files.get('dist/cli.js')?.mode !== 0o755) throw new Error('packed CLI is not executable (expected mode 0755)')

process.stdout.write(`Package contents verified: ${files.size} files, executable CLI.\n`)
