import fs from 'node:fs'
import path from 'node:path'
import { collectCiText, collectCiWorkflows, collectDeploymentText, collectOperationalDocs, existsInside, gitTrackedFiles, readSafeText } from './files.js'
import type { ScanContext } from './types.js'

function readPackageJson(directory: string, relativePath = 'package.json'): Record<string, unknown> | null {
  try {
    const source = readSafeText(directory, relativePath)
    if (source === null) return null
    const parsed: unknown = JSON.parse(source)
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

function isOpenMercatoMonorepo(root: string, manifest: Record<string, unknown>): boolean {
  const workspaces = manifest.workspaces
  const packages = Array.isArray(workspaces) ? workspaces
    : workspaces && typeof workspaces === 'object' ? (workspaces as Record<string, unknown>).packages : null
  if (!Array.isArray(packages) || !packages.some((entry) => typeof entry === 'string')) return false
  if (readPackageJson(root, 'packages/core/package.json')?.name !== '@open-mercato/core') return false
  return manifest.name === 'open-mercato'
    || readPackageJson(root, 'packages/create-app/package.json')?.name === 'create-mercato-app'
}

type ScanTarget = { root: string, kind: 'app' | 'monorepo' }

export function findScanTarget(start: string): ScanTarget | null {
  let current: string
  try {
    current = fs.realpathSync(path.resolve(start))
    if (fs.lstatSync(current).isFile()) current = path.dirname(current)
  } catch {
    return null
  }
  let app: ScanTarget | null = null
  while (true) {
    const manifest = readPackageJson(current)
    // Inspect all ancestors: the monorepo's internal app also looks like a generated app.
    if (manifest && isOpenMercatoMonorepo(current, manifest)) return { root: current, kind: 'monorepo' }
    if (!app && manifest && hasOpenMercatoCore(manifest) && existsInside(current, 'src/modules.ts')) {
      app = { root: current, kind: 'app' }
    }
    const parent = path.dirname(current)
    if (parent === current) return app
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
    collectOperationalDocs: () => collectOperationalDocs(root),
    collectCiText: () => collectCiText(root),
    collectCiWorkflows: () => collectCiWorkflows(root),
  }
}
