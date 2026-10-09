import fs from 'node:fs'
import path from 'node:path'
import { collectDeploymentText, existsInside, gitTrackedFiles, readSafeText } from './files.js'
import type { ScanContext } from './types.js'

function readPackageJson(directory: string): Record<string, unknown> | null {
  const file = path.join(directory, 'package.json')
  try {
    const stat = fs.lstatSync(file)
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1_048_576) return null
    const parsed: unknown = JSON.parse(fs.readFileSync(file, 'utf8'))
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null
  } catch {
    return null
  }
}

function hasOpenMercatoCore(manifest: Record<string, unknown>): boolean {
  for (const key of ['dependencies', 'devDependencies']) {
    const dependencies = manifest[key]
    if (dependencies && typeof dependencies === 'object' && !Array.isArray(dependencies)
      && Object.hasOwn(dependencies, '@open-mercato/core')) return true
  }
  return false
}

export function findAppRoot(start: string): string | null {
  let current = path.resolve(start)
  try {
    if (fs.lstatSync(current).isFile()) current = path.dirname(current)
  } catch {
    return null
  }
  while (true) {
    const manifest = readPackageJson(current)
    if (manifest && hasOpenMercatoCore(manifest) && existsInside(current, 'src/modules.ts')) return current
    const parent = path.dirname(current)
    if (parent === current) return null
    current = parent
  }
}

export function createScanContext(root: string): ScanContext {
  const packageJson = readPackageJson(root)
  if (!packageJson) throw new Error('The Open Mercato app package.json could not be read.')
  return {
    root,
    packageJson,
    trackedFiles: gitTrackedFiles(root),
    exists: (relativePath) => existsInside(root, relativePath),
    readText: (relativePath) => readSafeText(root, relativePath),
    collectDeploymentText: () => collectDeploymentText(root),
  }
}
