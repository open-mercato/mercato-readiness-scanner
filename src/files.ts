import fs from 'node:fs'
import os from 'node:os'
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

export function isLiveEnvPath(relativePath: string): boolean {
  const basename = path.posix.basename(normalized(relativePath)).toLowerCase()
  return basename.startsWith('.env') && !SAFE_ENV_TEMPLATES.has(basename)
}

export function isCredentialPath(relativePath: string): boolean {
  const normalizedPath = normalized(relativePath)
  const basename = path.posix.basename(normalizedPath).toLowerCase()
  return /\.(?:pem|key|p12|pfx|jks)$/i.test(basename)
    || ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_xmss', '.mcp.json', '.npmrc'].includes(basename)
    || /(?:^|\/)\.(?:codex|cursor)\/mcp\.json$/i.test(normalizedPath)
    || /(?:^|\/)\.aws\/credentials$/i.test(normalizedPath)
    || /(?:^|\/)\.config\/gcloud\/application_default_credentials\.json$/i.test(normalizedPath)
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
  if (isLiveEnvPath(relativePath) || isCredentialPath(relativePath)) return null
  const absolute = resolveInside(root, relativePath)
  if (!absolute) return null
  try {
    const stat = fs.lstatSync(absolute)
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > MAX_TEXT_BYTES || !resolvesWithinRoot(root, absolute)) return null
    return fs.readFileSync(absolute, 'utf8')
  } catch {
    return null
  }
}

export function gitTrackedFiles(root: string): ReadonlySet<string> | null {
  const result = spawnSync('git', ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', 'ls-files', '-z'], {
    cwd: root,
    env: { ...process.env, GIT_OPTIONAL_LOCKS: '0', GIT_CONFIG_NOSYSTEM: '1' },
    encoding: 'utf8',
    timeout: 5_000,
    maxBuffer: 4 * MAX_TEXT_BYTES,
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  if (result.error || result.status !== 0) return null
  return new Set(result.stdout.split('\0').filter(Boolean).map(normalized))
}

export function gitignoredPaths(source: string, paths: readonly string[]): ReadonlySet<string> | null {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'mercato-readiness-ignore-'))
  const environment = {
    ...process.env,
    GIT_OPTIONAL_LOCKS: '0',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
  }
  try {
    fs.writeFileSync(path.join(temporary, '.gitignore'), source, { mode: 0o600 })
    const initialized = spawnSync('git', ['init', '--quiet'], {
      cwd: temporary, env: environment, encoding: 'utf8', timeout: 5_000, stdio: ['ignore', 'ignore', 'ignore'],
    })
    if (initialized.error || initialized.status !== 0) return null
    const ignored = new Set<string>()
    for (const candidate of paths) {
      const result = spawnSync('git', [
        '-c', 'core.fsmonitor=false',
        '-c', 'core.hooksPath=/dev/null',
        '-c', 'core.excludesFile=/dev/null',
        'check-ignore', '--no-index', '--quiet', '--', candidate,
      ], { cwd: temporary, env: environment, encoding: 'utf8', timeout: 5_000, stdio: ['ignore', 'ignore', 'ignore'] })
      if (result.error || (result.status !== 0 && result.status !== 1)) return null
      if (result.status === 0) ignored.add(candidate)
    }
    return ignored
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true })
  }
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
      entries = fs.readdirSync(directory, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue
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
  return files.flatMap((file) => {
    const source = readSafeText(root, file)
    if (source === null) return []
    if (/\.(?:md|mdx|txt)$/i.test(file)) return [source]
    return [source.split(/\r?\n/).filter((line) => !/^\s*#/.test(line)).join('\n')]
  }).join('\n')
}

export function collectOperationalDocs(root: string): string {
  const files = ['.ai/guides/production-deployment.md', ...collectTextFiles(root, 'docs', /\.(?:md|mdx|txt)$/i)]
  return files.flatMap((file) => {
    const source = readSafeText(root, file)
    if (source === null) return []
    const withoutComments = source.replace(/<!--[\s\S]*?-->/g, '')
    return [withoutComments.split(/\r?\n/).filter((line) => !/\b(?:TODO|TBD)\b/i.test(line)).join('\n')]
  }).join('\n')
}

export function collectCiText(root: string): string {
  return collectCiWorkflows(root).map(({ source }) => source).join('\n---\n')
}

export function collectCiWorkflows(root: string): Array<{ path: string, source: string }> {
  const files = collectTextFiles(root, '.github/workflows', /\.(?:yml|yaml)$/i)
  return files.flatMap((file) => {
    const source = readSafeText(root, file)
    return source === null ? [] : [{ path: file, source }]
  })
}
