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

function isForbiddenEnv(relativePath: string): boolean {
  const basename = path.posix.basename(normalized(relativePath)).toLowerCase()
  return (basename === '.env' || basename.startsWith('.env.')) && !SAFE_ENV_TEMPLATES.has(basename)
}

export function existsInside(root: string, relativePath: string): boolean {
  const absolute = resolveInside(root, relativePath)
  if (!absolute) return false
  try {
    const stat = fs.lstatSync(absolute)
    return !stat.isSymbolicLink()
  } catch {
    return false
  }
}

export function readSafeText(root: string, relativePath: string): string | null {
  if (isForbiddenEnv(relativePath)) return null
  const absolute = resolveInside(root, relativePath)
  if (!absolute) return null
  try {
    const stat = fs.lstatSync(absolute)
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_TEXT_BYTES) return null
    return fs.readFileSync(absolute, 'utf8')
  } catch {
    return null
  }
}

export function gitTrackedFiles(root: string): ReadonlySet<string> | null {
  const result = spawnSync('git', ['ls-files', '-z'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 5_000,
    maxBuffer: 4 * MAX_TEXT_BYTES,
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  if (result.error || result.status !== 0) return null
  return new Set(result.stdout.split('\0').filter(Boolean).map(normalized))
}

function collectDocs(root: string): string[] {
  const docsRoot = resolveInside(root, 'docs')
  if (!docsRoot || !fs.existsSync(docsRoot)) return []
  const found: string[] = []
  let visitedDirectories = 0
  const visit = (directory: string, depth: number): void => {
    if (found.length >= 200 || visitedDirectories >= 500 || depth > 12) return
    visitedDirectories += 1
    let entries: fs.Dirent[]
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) visit(absolute, depth + 1)
      else if (entry.isFile() && /\.(?:md|mdx|txt)$/i.test(entry.name)) found.push(normalized(path.relative(root, absolute)))
      if (found.length >= 200) return
    }
  }
  visit(docsRoot, 0)
  return found
}

export function collectDeploymentText(root: string): string {
  const files = [...DEPLOYMENT_FILES, ...collectDocs(root)]
  return files.map((file) => readSafeText(root, file)).filter((value): value is string => value !== null).join('\n')
}

export function isLiveEnvPath(relativePath: string): boolean {
  const normalizedPath = normalized(relativePath)
  const basename = path.posix.basename(normalizedPath).toLowerCase()
  return (basename === '.env' || basename.startsWith('.env.')) && !SAFE_ENV_TEMPLATES.has(basename)
}
