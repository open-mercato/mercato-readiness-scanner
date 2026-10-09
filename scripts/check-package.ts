import { spawnSync } from 'node:child_process'

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const packed = spawnSync(npmCommand, ['pack', '--dry-run', '--json'], {
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'inherit'],
})

if (packed.error || packed.status !== 0) {
  throw packed.error ?? new Error(`npm pack exited with ${packed.status}`)
}

type PackedFile = { path: string; mode: number }
type PackedReport = { files: PackedFile[] }
const reports = JSON.parse(packed.stdout) as PackedReport[]
const report = Array.isArray(reports) ? reports[0] : null
if (!report || !Array.isArray(report.files)) throw new Error('npm pack did not return a file inventory')

const files = new Map(report.files.map((entry) => [entry.path, entry]))
for (const required of ['package.json', 'README.md', 'LICENSE', 'dist/cli.js', 'dist/index.js', 'dist/index.d.ts', 'docs/report.schema.json']) {
  if (!files.has(required)) throw new Error(`packed package is missing ${required}`)
}
for (const forbidden of ['src/', 'test/', 'scripts/']) {
  if ([...files.keys()].some((entry) => entry.startsWith(forbidden))) throw new Error(`packed package contains ${forbidden}`)
}
for (const entry of files.keys()) {
  if (/(?:^|\/)\.env|\.(?:pem|key|p12|pfx|jks)$|(?:^|\/)\.npmrc$/.test(entry)) {
    throw new Error(`packed package contains a sensitive path: ${entry}`)
  }
}
if (files.get('dist/cli.js')?.mode !== 0o755) throw new Error('packed CLI is not executable (expected mode 0755)')

process.stdout.write(`Package contents verified: ${files.size} files, executable CLI.\n`)
