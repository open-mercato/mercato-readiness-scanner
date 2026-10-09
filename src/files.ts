import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

const MAX_TEXT_BYTES = 1_048_576
const SAFE_ENV_TEMPLATES = new Set(['.env.example', '.env.sample', '.env.template'])
const DEPLOYMENT_FILES = [
  'Dockerfile',
  'docker-compose.yml',
  'docker-compose.fullapp.yml',
  'railway.toml',
  'railway.worker.toml',
  'scripts/railway-start.sh',
  'scripts/railway-worker.sh',
  'docker/scripts/init-or-migrate.sh',
  '.ai/guides/production-deployment.md',
] as const

function normalized(relativePath: string): string {
  return relativePath.replaceAll(path.sep, '/')
}

function resolveInside(root: string, relativePath: string): string | null {
  if (path.isAbsolute(relativePath)) return null
  const absolute = path.resolve(root, relativePath)
  const relation = path.relative(root, absolute)
  if (relation === '..' || relation.startsWith(`..${path.sep}`) || path.isAbsolute(relation)) return null
  return absolute
}

function resolvesWithinRoot(root: string, absolute: string): boolean {
  try {
    const realRoot = fs.realpathSync(root)
    const realTarget = fs.realpathSync(absolute)
    const relation = path.relative(realRoot, realTarget)
    return relation !== '..' && !relation.startsWith(`..${path.sep}`) && !path.isAbsolute(relation)
  } catch {
    return false
  }
}

function isForbiddenEnv(relativePath: string): boolean {
  const basename = path.posix.basename(normalized(relativePath)).toLowerCase()
  return basename.startsWith('.env') && !SAFE_ENV_TEMPLATES.has(basename)
}

function isForbiddenCredential(relativePath: string): boolean {
  const normalizedPath = normalized(relativePath).toLowerCase()
  const basename = path.posix.basename(normalizedPath).toLowerCase()
  return /\.(?:pem|key|p12|pfx|jks)$/i.test(basename)
    || ['id_rsa', 'id_ed25519', '.mcp.json', '.npmrc', '.netrc', '.git-credentials', 'credentials', 'credentials.json', 'token', 'tokens.json'].includes(basename)
    || /(?:^|\/)(?:\.ssh|\.aws|\.azure|\.gnupg|\.kube|\.secrets|secrets|\.config\/gcloud|\.git)(?:\/|$)/.test(normalizedPath)
    || /(?:^|\/)\.(?:codex|cursor)\/mcp\.json$/i.test(normalizedPath)
}

export function existsInside(root: string, relativePath: string): boolean {
  const absolute = resolveInside(root, relativePath)
  if (!absolute) return false
  try {
    const stat = fs.lstatSync(absolute)
    return !stat.isSymbolicLink() && resolvesWithinRoot(root, absolute)
  } catch {
    return false
  }
}

export function readSafeText(root: string, relativePath: string): string | null {
  if (isForbiddenEnv(relativePath) || isForbiddenCredential(relativePath)) return null
  return readBoundedText(root, relativePath)
}

// Dedicated allowlist for explicitly authorized production environment inspection.
export const PRODUCTION_ENV_FILES = ['.env', '.env.production', '.env.local', '.env.production.local'] as const

export function readProductionEnvText(root: string, relativePath: string): string | null {
  if (!(PRODUCTION_ENV_FILES as readonly string[]).includes(relativePath)) return null
  return readBoundedText(root, relativePath)
}

function readBoundedText(root: string, relativePath: string): string | null {
  const absolute = resolveInside(root, relativePath)
  if (!absolute) return null
  let descriptor: number | undefined
  try {
    const stat = fs.lstatSync(absolute)
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_TEXT_BYTES || !resolvesWithinRoot(root, absolute)) return null
    descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0))
    const opened = fs.fstatSync(descriptor)
    if (!opened.isFile() || opened.size > MAX_TEXT_BYTES) return null
    const buffer = Buffer.alloc(MAX_TEXT_BYTES + 1)
    let bytes = 0
    while (bytes < buffer.length) {
      const count = fs.readSync(descriptor, buffer, bytes, buffer.length - bytes, null)
      if (count === 0) break
      bytes += count
    }
    return bytes > MAX_TEXT_BYTES ? null : buffer.toString('utf8', 0, bytes)
  } catch {
    return null
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
  }
}

export type PermissionInspection = { mode: number; directory: boolean; symbolicLink: boolean }

export type StorageInspection = { inspected: number; unsafe: number; incomplete: boolean }

export function inspectStoragePermissions(root: string, location: string): StorageInspection | null {
  const absolute = path.isAbsolute(location) ? location : resolveInside(root, location)
  if (!absolute || !fs.existsSync(absolute)) return null
  const result: StorageInspection = { inspected: 0, unsafe: 0, incomplete: false }
  let parent = absolute
  try {
    while (true) {
      if (fs.lstatSync(parent).isSymbolicLink()) return { ...result, incomplete: true }
      const next = path.dirname(parent)
      if (next === parent) break
      parent = next
    }
  } catch {
    return { ...result, incomplete: true }
  }
  const visit = (file: string, depth: number): void => {
    if (depth > 12 || result.inspected >= 5_000) { result.incomplete = true; return }
    try {
      const stat = fs.lstatSync(file)
      result.inspected += 1
      if (stat.isSymbolicLink()) { result.incomplete = true; return }
      const mode = stat.mode & 0o777
      if ((mode & 0o007) !== 0 || (mode & 0o400) === 0 || (!stat.isDirectory() && (mode & 0o111) !== 0)
        || (stat.isDirectory() && (mode & 0o300) !== 0o300)) result.unsafe += 1
      if (stat.isDirectory()) {
        for (const entry of fs.readdirSync(file).sort()) {
          visit(path.join(file, entry), depth + 1)
          if (result.inspected >= 5_000) { result.incomplete = true; break }
        }
      }
    } catch {
      result.incomplete = true
    }
  }
  visit(absolute, 0)
  return result
}

export function inspectPermissions(root: string, relativePath: string): PermissionInspection | null {
  // Explicit storage paths may point at a mounted Railway volume. Only stat metadata is read.
  const absolute = path.isAbsolute(relativePath) ? relativePath : resolveInside(root, relativePath)
  if (!absolute) return null
  try {
    const stat = fs.lstatSync(absolute)
    return { mode: stat.mode & 0o777, directory: stat.isDirectory(), symbolicLink: stat.isSymbolicLink() }
  } catch {
    return null
  }
}

export function gitTrackedFiles(root: string): ReadonlySet<string> | null {
  const result = spawnSync('git', ['-c', 'core.fsmonitor=false', 'ls-files', '-z'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 5_000,
    maxBuffer: 4 * MAX_TEXT_BYTES,
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  if (result.error || result.status !== 0) return null
  return new Set(result.stdout.split('\0').filter(Boolean).map(normalized).sort())
}

function collectTextFiles(root: string, relativeRoot: string, allowed: RegExp): string[] {
  const docsRoot = resolveInside(root, relativeRoot)
  if (!docsRoot || !fs.existsSync(docsRoot)) return []
  try {
    if (fs.lstatSync(docsRoot).isSymbolicLink() || !resolvesWithinRoot(root, docsRoot)) return []
  } catch {
    return []
  }
  const found: string[] = []
  let visitedDirectories = 0
  const visit = (directory: string, depth: number): void => {
    if (found.length >= 200 || visitedDirectories >= 500 || depth > 12) return
    visitedDirectories += 1
    let entries: fs.Dirent[]
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)
    } catch {
      return
    }
    for (const entry of entries) {
      const relative = normalized(path.relative(root, path.join(directory, entry.name)))
      if (entry.isSymbolicLink() || isForbiddenEnv(relative) || isForbiddenCredential(relative)) continue
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) visit(absolute, depth + 1)
      else if (entry.isFile() && allowed.test(entry.name)) found.push(normalized(path.relative(root, absolute)))
      if (found.length >= 200) return
    }
  }
  visit(docsRoot, 0)
  return found
}

export function collectDeploymentText(root: string): string {
  const files = [...DEPLOYMENT_FILES, ...collectTextFiles(root, 'docs', /\.(?:md|mdx|txt)$/i)]
  return files.map((file) => readSafeText(root, file)).filter((value): value is string => value !== null).join('\n')
}

export function collectCiText(root: string): string {
  const files = collectTextFiles(root, '.github/workflows', /\.(?:yml|yaml)$/i)
  return files.map((file) => readSafeText(root, file)).filter((value): value is string => value !== null).join('\n')
}

export function isLiveEnvPath(relativePath: string): boolean {
  return isForbiddenEnv(relativePath)
}
