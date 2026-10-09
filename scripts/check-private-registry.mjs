import fs from 'node:fs'

const manifest = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
if (manifest.private !== true) throw new Error('package.json must keep private: true')
if (typeof manifest.name !== 'string' || !manifest.name.startsWith('@open-mercato/')) throw new Error('package.json must define the private Open Mercato package name')

const endpoint = `https://registry.npmjs.org/${encodeURIComponent(manifest.name)}`
const response = await fetch(endpoint, { signal: AbortSignal.timeout(10_000), headers: { accept: 'application/json' } })
if (response.status === 404) {
  process.stdout.write(`Public npm registry confirms ${manifest.name} is unpublished.\n`)
  process.exit(0)
}
if (response.ok) throw new Error(`${manifest.name} is publicly available on npm; publication is forbidden`)
throw new Error(`npm registry state could not be verified (HTTP ${response.status})`)
