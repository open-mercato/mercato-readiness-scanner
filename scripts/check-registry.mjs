import fs from 'node:fs'

const manifest = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
if (manifest.private === true) throw new Error('The npm release must be publishable')
if (manifest.name !== 'mercato-readiness-scanner') throw new Error('Unexpected npm package name')
if (manifest.bin?.['mercato-readiness-scanner'] !== 'dist/cli.js') throw new Error('The npx command must point to dist/cli.js')
if (manifest.publishConfig?.access !== 'public') throw new Error('The npm package must use public access')

const endpoint = `https://registry.npmjs.org/${encodeURIComponent(manifest.name)}`
const response = await fetch(endpoint, { signal: AbortSignal.timeout(10_000), headers: { accept: 'application/json' } })
if (response.status === 404) {
  process.stdout.write(`${manifest.name} is available for its first npm release.\n`)
} else if (response.ok) {
  const published = await response.json()
  if (published.name !== manifest.name || published.repository?.url !== manifest.repository.url) {
    throw new Error('The published npm package does not match this repository')
  }
  process.stdout.write(`${manifest.name} is published from the expected repository.\n`)
} else {
  throw new Error(`npm registry state could not be verified (HTTP ${response.status})`)
}
