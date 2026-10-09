import { isIP } from 'node:net'
import { parseEnv } from 'node:util'
import { minVersion, validRange } from 'semver'
import { parse, parseAllDocuments } from 'yaml'
import { isCredentialPath, isLiveEnvPath } from './files.js'
import type { RuleCheck, RuleDefinition, ScanContext, Severity } from './types.js'

const DOCS_BASE = 'https://github.com/open-mercato/mercato-readiness-scanner/blob/main/docs/rules'

type RuleInput = {
  id: string
  title: string
  category: string
  severity: Severity
  remediation: string
  check: (context: ScanContext) => RuleCheck
}

function rule(input: RuleInput): RuleDefinition {
  return { ...input, docsUrl: `${DOCS_BASE}/${input.id}.md` }
}

function scripts(context: ScanContext): Record<string, string> {
  const value = context.packageJson.scripts
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  return Object.fromEntries(Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === 'string'))
}

function dependencies(context: ScanContext): ReadonlySet<string> {
  const names: string[] = []
  for (const field of ['dependencies', 'devDependencies']) {
    const value = context.packageJson[field]
    if (value && typeof value === 'object' && !Array.isArray(value)) names.push(...Object.keys(value))
  }
  return new Set(names)
}

type TemplateInventory = {
  names: ReadonlySet<string>
  booleans: ReadonlyMap<string, boolean>
  integers: ReadonlyMap<string, number>
  enums: ReadonlyMap<string, string>
}

function templateInventory(context: ScanContext): TemplateInventory {
  const source = context.readText('.env.example') ?? ''
  const names = new Set<string>()
  const booleans = new Map<string, boolean>()
  const integers = new Map<string, number>()
  const enums = new Map<string, string>()
  let values: Record<string, string | undefined> = {}
  try {
    values = parseEnv(source)
  } catch {
    values = {}
  }
  for (const [key, rawValue] of Object.entries(values)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(key) || rawValue === undefined) continue
    names.add(key)
    const normalizedValue = rawValue.trim()
    if (/(?:DEBUG|PROFILE|DEVTOOLS|AUTOLOGIN|TEST_INJECT|DEMO_MODE|EMERGENCY_BYPASS|INTEGRATION_TEST|AUTO_SPAWN_WORKERS)/.test(key)) {
      if (/^(?:1|true|yes|y|on|enabled)$/i.test(normalizedValue)) booleans.set(key, true)
      if (/^(?:0|false|no|n|off|disabled)$/i.test(normalizedValue)) booleans.set(key, false)
    }
    if (key === 'RATE_LIMIT_TRUST_PROXY_DEPTH' && /^-?\d+$/.test(normalizedValue)) integers.set(key, Number(normalizedValue))
    if (key === 'CACHE_STRATEGY' && /^(?:redis|memory|sqlite)$/i.test(normalizedValue)) enums.set(key, normalizedValue.toLowerCase())
  }
  return { names, booleans, integers, enums }
}

function containsAll(source: string, values: string[]): boolean {
  return values.every((value) => source.includes(value))
}

function fileEvidence(paths: string[]): string[] {
  return paths.map((entry) => `Detected ${entry}.`)
}

function displayPath(value: string): string {
  return value.replace(/[\u0000-\u001F\u007F]/g, '?').slice(0, 240)
}

function ignorePatterns(context: ScanContext): ReadonlySet<string> {
  const source = context.readText('.gitignore') ?? ''
  return new Set(source.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#')))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function isLoopbackBinding(value: string): boolean {
  const normalized = value.replace(/^['"]|['"]$/g, '').trim()
  if (normalized.startsWith('[')) {
    const closing = normalized.indexOf(']')
    return closing > 0 && normalized[closing + 1] === ':' && isLoopbackHost(normalized.slice(1, closing))
  }
  const separator = normalized.indexOf(':')
  return separator > 0 && isLoopbackHost(normalized.slice(0, separator))
}

function isLoopbackHost(value: unknown): boolean {
  if (typeof value !== 'string') return false
  const normalized = value.trim().toLowerCase()
  if (normalized === 'localhost') return true
  if (isIP(normalized) === 4) return normalized.startsWith('127.')
  if (isIP(normalized) !== 6) return false
  const halves = normalized.split('::')
  if (halves.length > 2) return false
  const left = halves[0] ? halves[0].split(':') : []
  const right = halves[1] ? halves[1].split(':') : []
  const missing = halves.length === 2 ? 8 - left.length - right.length : 0
  const groups = [...left, ...Array.from({ length: missing }, () => '0'), ...right]
  return groups.length === 8 && groups.slice(0, 7).every((group) => Number.parseInt(group || '0', 16) === 0) && Number.parseInt(groups[7] ?? '0', 16) === 1
}

function composePublicBindings(context: ScanContext): string[] {
  const findings: string[] = []
  for (const file of ['docker-compose.yml', 'docker-compose.fullapp.yml']) {
    const source = context.readText(file)
    if (!source) continue
    let root: unknown
    try {
      root = parse(source, { merge: true })
    } catch {
      findings.push(`${file}: Compose configuration could not be safely parsed`)
      continue
    }
    if (!isRecord(root) || !isRecord(root.services)) {
      findings.push(`${file}: Compose services could not be safely inspected`)
      continue
    }
    for (const [name, value] of Object.entries(root.services)) {
      if (!isRecord(value)) continue
      const image = typeof value.image === 'string' ? value.image : ''
      if (!/(?:postgres|redis|search|opensearch|elastic|meili)/i.test(`${name}\n${image}`)) continue
      if (value.network_mode === 'host') findings.push(`${file}: ${name} uses host networking`)
      if (value.ports === undefined) continue
      if (!Array.isArray(value.ports)) {
        findings.push(`${file}: ${name} uses unsupported ports syntax`)
        continue
      }
      for (const port of value.ports) {
        if (typeof port === 'string' || typeof port === 'number') {
          const binding = String(port)
          if (!isLoopbackBinding(binding)) findings.push(`${file}: ${name} publishes ${displayPath(binding)}`)
        } else if (isRecord(port)) {
          if (!isLoopbackHost(port.host_ip)) findings.push(`${file}: ${name} publishes a long-syntax port`)
        } else {
          findings.push(`${file}: ${name} uses unsupported ports syntax`)
        }
      }
    }
  }
  return findings
}

function uncommented(source: string): string {
  let output = ''
  let quote = ''
  let escaped = false
  let blockComment = false
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index] ?? ''
    const next = source[index + 1] ?? ''
    if (blockComment) {
      if (character === '*' && next === '/') {
        blockComment = false
        index += 1
      } else if (character === '\n') output += '\n'
      continue
    }
    if (quote) {
      output += character
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === quote) quote = ''
      continue
    }
    if (character === '"' || character === "'" || character === '`') {
      quote = character
      output += character
      continue
    }
    if (character === '/' && next === '*') {
      blockComment = true
      index += 1
      continue
    }
    if (character === '/' && next === '/') {
      while (index < source.length && source[index] !== '\n') index += 1
      output += '\n'
      continue
    }
    if (character === '#' && (index === 0 || /\s/.test(source[index - 1] ?? ''))) {
      while (index < source.length && source[index] !== '\n') index += 1
      output += '\n'
      continue
    }
    output += character
  }
  return output
}

const DEPLOYMENT_FILES = ['Dockerfile', 'railway.toml', 'railway.worker.toml', 'scripts/railway-start.sh', 'scripts/railway-worker.sh', 'docker/scripts/init-or-migrate.sh'] as const
const COMPOSE_FILES = ['docker-compose.yml', 'docker-compose.fullapp.yml'] as const

function executableDeploymentText(context: ScanContext): string {
  return DEPLOYMENT_FILES
    .map((file) => uncommented(context.readText(file) ?? ''))
    .join('\n')
}

function isWorkerCommand(value: string): boolean {
  return /(?:^|[;&]\s*)(?:exec\s+)?(?:(?:yarn|pnpm)(?:\s+run)?\s+(?:mercato\s+)?worker|npm\s+run\s+(?:mercato\s+)?worker|mercato\s+worker)(?:\s|$)/im.test(value)
}

function composeServices(context: ScanContext, file: string): Array<[string, Record<string, unknown>]> | null {
  const source = context.readText(file)
  if (!source) return []
  try {
    const root: unknown = parse(source, { merge: true })
    if (!isRecord(root) || !isRecord(root.services)) return null
    return Object.entries(root.services).filter((entry): entry is [string, Record<string, unknown>] => isRecord(entry[1]))
  } catch {
    return null
  }
}

function workerDefinitions(context: ScanContext): string[] {
  const paths: string[] = []
  const railway = context.readText('railway.worker.toml')
  if (railway) {
    const command = uncommented(railway).match(/(?:startCommand|command)\s*=\s*["']([^"']+)["']/i)?.[1]
    if (command && isWorkerCommand(command)) paths.push('railway.worker.toml')
  }
  const script = context.readText('scripts/railway-worker.sh')
  if (script && isWorkerCommand(uncommented(script))) paths.push('scripts/railway-worker.sh')
  for (const file of COMPOSE_FILES) {
    const services = composeServices(context, file)
    if (services?.some(([, value]) => {
      const command = Array.isArray(value.command) ? value.command.join(' ') : String(value.command ?? '')
      return isWorkerCommand(command)
    })) paths.push(file)
  }
  return paths
}

type ArtifactParity = { mismatch: boolean, complete: boolean, evidence: string[] }

function composeArtifact(value: Record<string, unknown>): string | null {
  if (typeof value.image === 'string') return `image:${value.image}`
  if (typeof value.build === 'string') {
    const prefix = value.build === '.' ? '' : `${value.build.replace(/\/$/, '')}/`
    return `dockerfile:${prefix}Dockerfile`
  }
  if (isRecord(value.build)) {
    const context = typeof value.build.context === 'string' ? value.build.context : '.'
    const dockerfile = typeof value.build.dockerfile === 'string' ? value.build.dockerfile : 'Dockerfile'
    const prefix = context === '.' ? '' : `${context.replace(/\/$/, '')}/`
    return `dockerfile:${prefix}${dockerfile}`
  }
  return null
}

function workerArtifactParity(context: ScanContext): ArtifactParity {
  const evidence: string[] = []
  const comparableArtifacts = new Map<string, Set<string>>()
  let complete = true
  let mismatch = false
  if (workerDefinitions(context).includes('railway.worker.toml')) {
    const web = uncommented(context.readText('railway.toml') ?? '')
    const worker = uncommented(context.readText('railway.worker.toml') ?? '')
    if (!web?.trim() || !worker?.trim()) complete = false
    else {
      const webArtifact = web.match(/dockerfilePath\s*=\s*["']([^"']+)["']/i)?.[1] ?? 'Dockerfile'
      const workerArtifact = worker.match(/dockerfilePath\s*=\s*["']([^"']+)["']/i)?.[1] ?? 'Dockerfile'
      evidence.push(`Railway web artifact: ${displayPath(webArtifact)}`, `Railway worker artifact: ${displayPath(workerArtifact)}`)
      if (webArtifact !== workerArtifact) mismatch = true
      const artifacts = comparableArtifacts.get('dockerfile') ?? new Set<string>()
      artifacts.add(`dockerfile:${webArtifact}`).add(`dockerfile:${workerArtifact}`)
      comparableArtifacts.set('dockerfile', artifacts)
    }
  }
  for (const file of COMPOSE_FILES) {
    const services = composeServices(context, file)
    if (services === null) {
      complete = false
      continue
    }
    const workers = services.filter(([, value]) => {
      const command = Array.isArray(value.command) ? value.command.join(' ') : String(value.command ?? '')
      return isWorkerCommand(command)
    })
    const web = services.find(([name, value]) => {
      const command = Array.isArray(value.command) ? value.command.join(' ') : String(value.command ?? '')
      return !isWorkerCommand(command) && /^(?:app|web|mercato)$/i.test(name)
    })
    if (!workers.length) {
      if (web && workerDefinitions(context).length > 0) {
        const webArtifact = composeArtifact(web[1])
        if (webArtifact) {
          evidence.push(`${file} web artifact: ${displayPath(webArtifact)}`)
          const kind = webArtifact.split(':', 1)[0] ?? ''
          const known = comparableArtifacts.get(kind) ?? new Set<string>()
          known.add(webArtifact)
          comparableArtifacts.set(kind, known)
        } else complete = false
      }
      continue
    }
    if (!web) {
      complete = false
      continue
    }
    const webArtifact = composeArtifact(web[1])
    if (!webArtifact) complete = false
    for (const [name, value] of workers) {
      const workerArtifact = composeArtifact(value)
      if (!workerArtifact || !webArtifact) {
        complete = false
        continue
      }
      evidence.push(`${file} web artifact: ${displayPath(webArtifact)}`, `${file} ${displayPath(name)} artifact: ${displayPath(workerArtifact)}`)
      if (webArtifact !== workerArtifact) mismatch = true
      for (const artifact of [webArtifact, workerArtifact]) {
        const kind = artifact.split(':', 1)[0] ?? ''
        const known = comparableArtifacts.get(kind) ?? new Set<string>()
        known.add(artifact)
        comparableArtifacts.set(kind, known)
      }
    }
  }
  if ([...comparableArtifacts.values()].some((artifacts) => artifacts.size > 1)) mismatch = true
  if (comparableArtifacts.size > 1) complete = false
  if (workerDefinitions(context).includes('scripts/railway-worker.sh')) complete = false
  return { mismatch, complete, evidence }
}

function finalDockerUser(source: string): string | null {
  const lines = source.split(/\r?\n/)
  const stages = new Map<string, { user: string | null }>()
  let current: { user: string | null } | null = null
  let stageIndex = 0
  for (const line of lines) {
    const from = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)(?:\s+AS\s+([^\s#]+))?/i)
    if (from?.[1]) {
      const inherited = stages.get(from[1].toLowerCase())?.user ?? null
      current = { user: inherited }
      stages.set(String(stageIndex), current)
      if (from[2]) stages.set(from[2].toLowerCase(), current)
      stageIndex += 1
      continue
    }
    const user = line.match(/^\s*USER\s+([^\s#]+)/i)?.[1]
    if (current && user) current.user = user.toLowerCase()
  }
  return current?.user ?? null
}

type WorkflowCommand = { command: string, blocking: boolean }

function constantBoolean(value: unknown, expected: boolean): boolean {
  if (value === expected) return true
  if (typeof value !== 'string') return false
  const token = expected ? 'true' : 'false'
  return new RegExp(`^(?:${token}|\\$\\{\\{\\s*${token}\\s*\\}\\})$`, 'i').test(value.trim())
}

function alwaysRuns(value: unknown): boolean {
  return value === undefined || constantBoolean(value, true)
}

function failureIsBlocking(value: unknown): boolean {
  return value === undefined || constantBoolean(value, false)
}

function shellPreservesFailure(value: unknown): boolean {
  if (value === undefined) return true
  if (typeof value !== 'string') return false
  const tokens = value.trim().split(/\s+/)
  const executable = tokens[0]?.split('/').at(-1)?.toLowerCase()
  if (executable !== 'bash' && executable !== 'sh') return false
  return tokens.some((token) => /^-[^-]*e[A-Za-z]*$/.test(token)) || /(?:^|\s)-o\s+errexit(?:\s|$)/i.test(value)
}

function workflowCommands(source: string): WorkflowCommand[] {
  const commands: WorkflowCommand[] = []
  for (const document of parseAllDocuments(source)) {
    if (document.errors.length) continue
    const root: unknown = document.toJS()
    if (!isRecord(root) || !isRecord(root.jobs)) continue
    const workflowDefaults = isRecord(root.defaults) && isRecord(root.defaults.run) ? root.defaults.run : null
    for (const value of Object.values(root.jobs)) {
      if (!isRecord(value) || !Array.isArray(value.steps)) continue
      const jobRuns = alwaysRuns(value.if)
      const jobBlocking = failureIsBlocking(value['continue-on-error'])
      const jobDefaults = isRecord(value.defaults) && isRecord(value.defaults.run) ? value.defaults.run : workflowDefaults
      for (const step of value.steps) {
        if (!isRecord(step) || typeof step.run !== 'string') continue
        const runs = jobRuns && alwaysRuns(step.if)
        const shell = step.shell ?? jobDefaults?.shell
        const blocking = jobBlocking && failureIsBlocking(step['continue-on-error']) && shellPreservesFailure(shell)
        if (runs && step.run.trim()) commands.push({ command: step.run, blocking })
      }
    }
  }
  return commands
}

function hasBlockingPackageCommand(commands: WorkflowCommand[], name: string): boolean {
  const pattern = new RegExp(`(?:^|[;&|]\\s*)(?:corepack\\s+)?(?:yarn(?:\\s+run)?|pnpm(?:\\s+run)?|npm(?:\\s+run)?)\\s+${name}\\b`, 'im')
  return commands.some(({ command, blocking }) => blocking && commandPreservesFailure(command) && pattern.test(command))
}

function hasBlockingMigrationCommand(commands: WorkflowCommand[]): boolean {
  return commands.some(({ command, blocking }) => blocking && commandPreservesFailure(command) && /(?:^|[;&|]\s*)(?:yarn|pnpm|npm(?:\s+run)?)\s+(?:db:migrate|mercato\s+db\s+migrate)\b/im.test(command))
}

function commandPreservesFailure(command: string): boolean {
  return !/\||(?:^|[^&])&(?!&)|\bset\s+\+e\b|;\s*exit\s+0\b/i.test(command)
}

type DependencyMutation = 'immutable' | 'mutable'

function dependencyMutation(command: string): DependencyMutation | null {
  const normalized = command
    .trim()
    .replace(/^(?:RUN|CMD|ENTRYPOINT)\s+/i, '')
    .replace(/^[A-Za-z][\w.-]*(?:Command|command)\s*=\s*["']?/i, '')
    .replace(/^["']/, '')
    .replace(/^(?:exec\s+|sudo\s+|corepack\s+)+/i, '')
    .trim()
  const match = normalized.match(/^(npm|yarn|pnpm)\s+([^\s"']+)([^\n]*)/i)
  if (!match?.[1] || !match[2]) return null
  const manager = match[1].toLowerCase()
  const action = match[2].toLowerCase()
  const args = match[3] ?? ''
  if (manager === 'npm') {
    if (action === 'ci') return 'immutable'
    if (['install', 'i', 'add', 'update', 'up'].includes(action)) return 'mutable'
    return null
  }
  if (manager === 'yarn') {
    if (action === 'install') return /(?:^|\s)--(?:immutable|frozen-lockfile)(?:\s|$)/i.test(args) ? 'immutable' : 'mutable'
    if (['add', 'update', 'up', 'upgrade'].includes(action)) return 'mutable'
    return null
  }
  if (action === 'install' || action === 'i') return /(?:^|\s)--frozen-lockfile(?:\s|$)/i.test(args) ? 'immutable' : 'mutable'
  if (['add', 'update', 'up'].includes(action)) return 'mutable'
  return null
}

function dependencyInstallationProof(context: ScanContext): { found: boolean, mutableSurfaces: string[] } {
  let found = false
  const mutableSurfaces: string[] = []
  for (const file of DEPLOYMENT_FILES) {
    const source = uncommented(context.readText(file) ?? '').replace(/\\\r?\n/g, ' ')
    if (!source.trim()) continue
    const mutations = source
      .split(/\r?\n|&&|\|\||;|&|\|/)
      .map(dependencyMutation)
      .filter((value): value is DependencyMutation => value !== null)
    if (!mutations.length) continue
    found = true
    if (mutations.at(-1) !== 'immutable') mutableSurfaces.push(file)
  }
  return { found, mutableSurfaces }
}

function extractDelimitedBody(source: string, openingIndex: number, opening: string, closing: string): string | null {
  let depth = 0
  let quote = ''
  let escaped = false
  for (let index = openingIndex; index < source.length; index += 1) {
    const character = source[index] ?? ''
    if (quote) {
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === quote) quote = ''
      continue
    }
    if (character === '"' || character === "'" || character === '`') {
      quote = character
      continue
    }
    if (character === opening) depth += 1
    if (character === closing) {
      depth -= 1
      if (depth === 0) return source.slice(openingIndex + 1, index)
    }
  }
  return null
}

function activeHeaderEvidence(source: string): string {
  const functionMatch = /(?:async\s+)?headers\s*\(\s*\)\s*\{|headers\s*:\s*(?:async\s*)?(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/m.exec(source)
  if (!functionMatch) return ''
  const openingBrace = source.indexOf('{', functionMatch.index)
  const body = extractDelimitedBody(source, openingBrace, '{', '}')
  if (!body) return ''
  const returned = /\breturn\s*\[/m.exec(body)
  if (!returned) return ''
  const openingBracket = body.indexOf('[', returned.index)
  const returnedEntries = extractDelimitedBody(body, openingBracket, '[', ']')
  if (!returnedEntries) return ''
  const evidence = [returnedEntries]
  for (const match of returnedEntries.matchAll(/\bheaders\s*:\s*([A-Za-z_$][\w$]*)\b/g)) {
    const identifier = match[1]
    if (!identifier) continue
    const declaration = new RegExp(`(?:const|let|var)\\s+${identifier.replace(/[$]/g, '\\$&')}\\s*=\\s*\\[([\\s\\S]*?)\\]`, 'm').exec(source)
    if (declaration?.[0]) evidence.push(declaration[0])
  }
  return evidence.join('\n')
}

function requiresNode24OrNewer(range: string): boolean {
  if (range.split('||').some((clause) => !clause.trim())) return false
  if (validRange(range) === null) return false
  const minimum = minVersion(range)
  return minimum !== null && minimum.major >= 24
}

export const RULES: readonly RuleDefinition[] = [
  rule({
    id: 'secrets-live-env-untracked', title: 'Live environment files are not tracked', category: 'Secrets', severity: 'critical',
    remediation: 'Remove value-bearing .env files from version control, rotate exposed credentials, and keep only sanitized example/sample/template files.',
    check: (context) => {
      if (!context.trackedFiles) return { status: 'warning', summary: 'Git tracking could not be inspected; verify that no live environment file is committed.' }
      const tracked = [...context.trackedFiles].filter(isLiveEnvPath)
      return tracked.length === 0
        ? { status: 'pass', summary: 'No value-bearing .env file is tracked.' }
        : { status: 'fail', summary: 'Value-bearing environment files are tracked.', evidence: tracked.map((file) => `Tracked sensitive path: ${displayPath(file)}`) }
    },
  }),
  rule({
    id: 'secrets-no-tracked-credentials', title: 'Credential and private-key files are not tracked', category: 'Secrets', severity: 'critical',
    remediation: 'Remove tracked credential or private-key files, revoke or rotate the material, and store it in an access-controlled secret manager.',
    check: (context) => {
      if (!context.trackedFiles) return { status: 'warning', summary: 'Git tracking could not be inspected; verify that no credential or private-key file is committed.' }
      const tracked = [...context.trackedFiles].filter(isCredentialPath)
      return tracked.length
        ? { status: 'fail', summary: 'Credential-like or private-key paths are tracked.', evidence: tracked.map((file) => `Tracked sensitive path: ${displayPath(file)}`) }
        : { status: 'pass', summary: 'No recognized credential or private-key path is tracked.' }
    },
  }),
  rule({
    id: 'secrets-ignore-policy', title: 'Sensitive local files are ignored', category: 'Secrets', severity: 'high',
    remediation: 'Ignore live .env files, private keys, local MCP credentials, npm credentials, and raw agent session exports.',
    check: (context) => {
      const patterns = ignorePatterns(context)
      if (!patterns.size) return { status: 'fail', summary: 'No readable .gitignore defines a sensitive-file policy.' }
      const required = ['.env', '.env.production', '.env.local', '.env.*.local', '*.pem', '*.key', '.mcp.json', '.npmrc', '.ai/session-exports/']
      const missing = required.filter((pattern) => !patterns.has(pattern))
      return missing.length === 0
        ? { status: 'pass', summary: 'The ignore policy covers common Open Mercato secret and session artifacts.' }
        : { status: 'fail', summary: 'The ignore policy misses sensitive local artifacts.', evidence: missing.map((pattern) => `Missing ignore coverage: ${pattern}`) }
    },
  }),
  rule({
    id: 'runtime-env-template', title: 'Production configuration has a sanitized template', category: 'Runtime', severity: 'high',
    remediation: 'Keep a sanitized .env.example with configuration names and safe placeholders for the exact app release.',
    check: (context) => {
      if (!context.exists('.env.example')) return { status: 'fail', summary: 'The application has no .env.example template.' }
      const inventory = templateInventory(context)
      const missing = ['NODE_ENV', 'APP_URL', 'DATABASE_URL', 'INTERNAL_APP_ORIGIN', 'PLATFORM_PRIMARY_HOST'].filter((key) => !inventory.names.has(key))
      return missing.length === 0
        ? { status: 'pass', summary: 'The sanitized environment template names the core production settings.' }
        : { status: 'fail', summary: 'The environment template omits core production settings.', evidence: missing.map((key) => `Missing template key: ${key}`) }
    },
  }),
  rule({
    id: 'runtime-production-scripts', title: 'Production build and start scripts are explicit', category: 'Runtime', severity: 'high',
    remediation: 'Define build and start scripts, and force NODE_ENV=production during the production build.',
    check: (context) => {
      const values = scripts(context)
      const missing = ['build', 'start'].filter((name) => !values[name])
      if (missing.length) return { status: 'fail', summary: 'Production lifecycle scripts are incomplete.', evidence: missing.map((name) => `Missing package script: ${name}`) }
      const build = values.build ?? ''
      const productionBuild = /(?:^|&&|;)\s*(?:cross-env\s+)?NODE_ENV=production\s+(?:(?:next|mercato)\s+build|(?:yarn|pnpm|npm(?:\s+run)?)\s+build(?::[A-Za-z0-9_-]+)?)(?:\s|$)/i.test(build)
      if (!productionBuild) return { status: 'fail', summary: 'The build script does not explicitly force NODE_ENV=production for the build command.' }
      return { status: 'pass', summary: 'Production build and start scripts are present and production mode is explicit.' }
    },
  }),
  rule({
    id: 'edge-tls-and-canonical-origin', title: 'TLS and canonical origin are verified at deployment', category: 'Edge', severity: 'critical',
    remediation: 'Serve every public route over HTTPS, redirect HTTP, verify certificate renewal, and set the canonical public origin to the real HTTPS URL.',
    check: (context) => {
      const source = context.collectDeploymentText()
      const hasTlsRunbook = /\b(?:https|tls|certificate)\b/i.test(source)
      return hasTlsRunbook
        ? { status: 'warning', summary: 'TLS guidance exists, but a static scan cannot verify the live certificate, redirect, DNS, or canonical origin.' }
        : { status: 'fail', summary: 'No deployment guidance records TLS and canonical-origin verification.' }
    },
  }),
  rule({
    id: 'edge-trusted-proxy-depth', title: 'Trusted proxy depth is topology-specific', category: 'Edge', severity: 'high',
    remediation: 'Set RATE_LIMIT_TRUST_PROXY_DEPTH to the exact number of trusted proxy hops and never trust arbitrary forwarded headers.',
    check: (context) => {
      const inventory = templateInventory(context)
      if (!inventory.names.has('RATE_LIMIT_TRUST_PROXY_DEPTH')) return { status: 'fail', summary: 'RATE_LIMIT_TRUST_PROXY_DEPTH is absent from the configuration template.' }
      const depth = inventory.integers.get('RATE_LIMIT_TRUST_PROXY_DEPTH')
      if (depth !== undefined && depth < 0) return { status: 'fail', summary: 'RATE_LIMIT_TRUST_PROXY_DEPTH cannot be negative.' }
      return { status: 'warning', summary: 'RATE_LIMIT_TRUST_PROXY_DEPTH is documented; verify its live value matches the deployed proxy chain.' }
    },
  }),
  rule({
    id: 'edge-allowed-origins', title: 'Browser and real-time origins are restricted', category: 'Edge', severity: 'high',
    remediation: 'Configure APP_ALLOWED_ORIGINS and capability-specific origin lists with only intended HTTPS origins.',
    check: (context) => {
      const inventory = templateInventory(context)
      const required = ['APP_ALLOWED_ORIGINS']
      const installed = dependencies(context)
      if (installed.has('@open-mercato/checkout')) required.push('CHECKOUT_ALLOWED_ORIGINS')
      if (installed.has('@open-mercato/documents')) required.push('DOCUMENTS_COLLAB_ALLOWED_ORIGINS')
      const missing = required.filter((key) => !inventory.names.has(key))
      return missing.length
        ? { status: 'fail', summary: 'Origin allowlist configuration is incomplete.', evidence: missing.map((key) => `Missing template key: ${key}`) }
        : { status: 'warning', summary: 'Origin allowlist keys are present; verify that live values contain only intended HTTPS origins.' }
    },
  }),
  rule({
    id: 'edge-security-headers', title: 'Application security headers are configured', category: 'Edge', severity: 'high',
    remediation: 'Keep the shared CSP and security headers in next.config.ts and verify that the public edge preserves them.',
    check: (context) => {
      const source = uncommented(context.readText('next.config.ts') ?? context.readText('next.config.mjs') ?? '')
      const activeHeaders = activeHeaderEvidence(source)
      const required = ['Content-Security-Policy', 'Referrer-Policy', 'X-Content-Type-Options']
      const missing = required.filter((header) => !activeHeaders.includes(header))
      if (!/X-Frame-Options|frame-ancestors/.test(activeHeaders)) missing.push('frame protection')
      if (!activeHeaders) missing.push('active Next.js headers configuration')
      return missing.length
        ? { status: 'fail', summary: 'The application configuration does not declare the complete security-header baseline.', evidence: missing.map((header) => `Missing header: ${header}`) }
        : { status: 'pass', summary: 'The application declares CSP, referrer, frame, and MIME-sniffing protection headers.' }
    },
  }),
  rule({
    id: 'operations-health-check', title: 'A deployment health check is wired', category: 'Operations', severity: 'high',
    remediation: 'Expose the standard health route and configure the deployment platform to probe it with bounded timeouts.',
    check: (context) => {
      const route = dependencies(context).has('@open-mercato/core') || context.exists('src/app/api/healthz/route.ts')
      const configured = /\/api\/healthz/.test(context.collectDeploymentText())
      if (route && configured) return { status: 'warning', summary: 'The health route is wired; verify bounded dependency-failure and recovery behavior in the deployed environment.' }
      const evidence = [!route ? 'Missing src/app/api/healthz/route.ts.' : '', !configured ? 'Deployment configuration does not reference /api/healthz.' : ''].filter(Boolean)
      return { status: 'fail', summary: 'Health-check wiring is incomplete.', evidence }
    },
  }),
  rule({
    id: 'infrastructure-private-services', title: 'Stateful services are not publicly published', category: 'Infrastructure', severity: 'critical',
    remediation: 'Remove public host bindings for PostgreSQL, Redis, and search services; use private networks or an authenticated operator tunnel.',
    check: (context) => {
      const composePresent = context.exists('docker-compose.yml') || context.exists('docker-compose.fullapp.yml')
      if (!composePresent) return { status: 'skipped', summary: 'No recognized in-repository Compose topology was found; verify provider networking separately.' }
      const findings = composePublicBindings(context)
      return findings.length
        ? { status: 'fail', summary: 'Stateful services have non-loopback host port bindings.', evidence: findings }
        : { status: 'pass', summary: 'No public host binding was found for recognized stateful services.' }
    },
  }),
  rule({
    id: 'container-non-root-user', title: 'Production containers run as non-root', category: 'Containers', severity: 'high',
    remediation: 'Create an unprivileged runtime user and switch to it with USER in the final production image.',
    check: (context) => {
      const source = context.readText('Dockerfile')
      if (!source) return { status: 'skipped', summary: 'No Dockerfile is present.' }
      const user = finalDockerUser(source)
      const userId = user?.split(':', 1)[0] ?? ''
      const nonRoot = userId !== '' && !/[${}]/.test(userId) && userId !== 'root' && !/^0+$/.test(userId)
      return nonRoot
        ? { status: 'pass', summary: 'The final container user is non-root.', evidence: ['A final USER directive is present.'] }
        : { status: 'fail', summary: 'The production image does not end with a non-root USER directive.' }
    },
  }),
  rule({
    id: 'supply-chain-immutable-install', title: 'Deployments use immutable dependency installation', category: 'Supply chain', severity: 'high',
    remediation: 'Commit one lockfile and use an immutable/frozen install in image and CI builds.',
    check: (context) => {
      const proof = dependencyInstallationProof(context)
      if (!proof.found) return { status: 'fail', summary: 'No immutable dependency installation was found in deployment configuration.' }
      return proof.mutableSurfaces.length === 0
        ? { status: 'pass', summary: 'Every detected deployment install surface ends with an immutable dependency install.' }
        : { status: 'fail', summary: 'A deployment surface can finish with a mutable dependency tree.', evidence: proof.mutableSurfaces.map((file) => `Mutable final install: ${file}`) }
    },
  }),
  rule({
    id: 'supply-chain-single-lockfile', title: 'Exactly one package lockfile is committed', category: 'Supply chain', severity: 'medium',
    remediation: 'Commit the lockfile for the selected package manager and remove competing lockfiles.',
    check: (context) => {
      const lockfiles = ['yarn.lock', 'package-lock.json', 'pnpm-lock.yaml'].filter(context.exists)
      return lockfiles.length === 1
        ? { status: 'pass', summary: `Exactly one package lockfile is present.`, evidence: fileEvidence(lockfiles) }
        : { status: 'fail', summary: lockfiles.length === 0 ? 'No package lockfile is present.' : 'Multiple package-manager lockfiles are present.', evidence: fileEvidence(lockfiles) }
    },
  }),
  rule({
    id: 'infrastructure-shared-redis', title: 'Multi-process deployments use shared Redis coordination', category: 'Infrastructure', severity: 'high',
    remediation: 'Use shared Redis-backed cache, events, and asynchronous queues whenever web and worker processes run separately.',
    check: (context) => {
      const hasWorker = workerDefinitions(context).length > 0
      if (!hasWorker) return { status: 'skipped', summary: 'No separate worker process was detected.' }
      const inventory = templateInventory(context)
      const strategy = inventory.enums.get('CACHE_STRATEGY')
      const redisNamed = ['REDIS_URL', 'CACHE_REDIS_URL', 'EVENTS_REDIS_URL'].some((key) => inventory.names.has(key))
      if (strategy && strategy !== 'redis') return { status: 'fail', summary: `The template selects ${strategy} cache coordination for a multi-process topology.` }
      if (strategy === 'redis' && redisNamed) return { status: 'warning', summary: 'Shared Redis configuration is represented; verify every live process uses the same service.' }
      return { status: 'fail', summary: 'A separate worker exists without a complete shared Redis configuration surface.' }
    },
  }),
  rule({
    id: 'release-database-migrations', title: 'Database migrations are part of release startup', category: 'Release', severity: 'high',
    remediation: 'Run the supported database migration command once per release before accepting traffic.',
    check: (context) => /(?:db[: ]migrate|mercato\s+db\s+migrate)/i.test(executableDeploymentText(context))
      ? { status: 'warning', summary: 'A migration path exists; verify exactly one controlled release job can execute it.' }
      : { status: 'fail', summary: 'No database migration step was found in deployment configuration.' },
  }),
  rule({
    id: 'release-immutable-artifact', title: 'Production deploys select an immutable artifact', category: 'Release', severity: 'high',
    remediation: 'Build once, identify the artifact by digest or commit SHA, and retain the prior compatible artifact for rollback.',
    check: (context) => {
      const source = ['docker-compose.yml', 'docker-compose.fullapp.yml', 'railway.toml', 'railway.worker.toml']
        .map((file) => context.readText(file) ?? '').join('\n')
      const images = [...source.matchAll(/^\s*image\s*[:=]\s*["']?([^\s"']+)/gmi)].map((match) => match[1] ?? '')
      if (!images.length) return { status: 'warning', summary: 'No in-repository production image reference proves immutable artifact selection.' }
      const mutable = images.filter((image) => /:latest$|:(?:main|master|develop|dev)$/i.test(image))
      if (mutable.length) return { status: 'fail', summary: 'Production configuration uses mutable image references.', evidence: mutable.map((image) => `Mutable image reference: ${displayPath(image)}`) }
      const unpinned = images.filter((image) => !/@sha256:[a-f0-9]{64}$/i.test(image) && !/:[a-f0-9]{7,40}$/i.test(image) && !/github\.sha/i.test(image))
      return unpinned.length
        ? { status: 'warning', summary: 'Image references exist, but the scanner cannot prove they are immutable.', evidence: unpinned.map((image) => `Review image reference: ${displayPath(image)}`) }
        : { status: 'pass', summary: 'Production image references use a digest or commit-derived identifier.' }
    },
  }),
  rule({
    id: 'release-validation-gate', title: 'Release validation gates the exact revision', category: 'Release', severity: 'high',
    remediation: 'Make generation, production build, tests, and migration verification blocking steps for the exact release revision.',
    check: (context) => {
      const source = context.collectCiText()
      if (!source) return { status: 'warning', summary: 'No recognized in-repository CI workflow was found; verify the external release gate.' }
      const commands = workflowCommands(source)
      const required = [
        ['generation', hasBlockingPackageCommand(commands, 'generate')],
        ['production build', hasBlockingPackageCommand(commands, 'build')],
        ['tests', hasBlockingPackageCommand(commands, 'test')],
        ['migration verification', hasBlockingMigrationCommand(commands)],
      ] as const
      const missing = required.filter(([, present]) => !present).map(([name]) => name)
      return missing.length
        ? { status: 'fail', summary: 'The release validation workflow is incomplete.', evidence: missing.map((name) => `Missing blocking stage: ${name}`) }
        : { status: 'pass', summary: 'CI represents generation, build, tests, and migration verification.' }
    },
  }),
  rule({
    id: 'operations-worker-topology', title: 'Background workers have an explicit process topology', category: 'Operations', severity: 'high',
    remediation: 'Deploy the supported worker process separately, keep its release aligned with the web app, and monitor both.',
    check: (context) => {
      if (!dependencies(context).has('@open-mercato/queue')) return { status: 'skipped', summary: 'The queue package is not installed.' }
      const paths = workerDefinitions(context)
      return paths.length
        ? { status: 'pass', summary: 'An explicit worker deployment surface is present.', evidence: fileEvidence(paths) }
        : { status: 'fail', summary: 'The queue package is installed but no worker deployment surface was found.' }
    },
  }),
  rule({
    id: 'workers-release-parity', title: 'Web and worker processes use the same release artifact', category: 'Operations', severity: 'high',
    remediation: 'Deploy one immutable build to web and worker roles and vary only the supported entrypoint.',
    check: (context) => {
      if (workerDefinitions(context).length === 0) return { status: 'skipped', summary: 'No separate worker process was detected.' }
      const parity = workerArtifactParity(context)
      if (parity.mismatch) return { status: 'fail', summary: 'Web and worker deployment definitions use different build artifacts.', evidence: parity.evidence }
      if (!parity.complete) return { status: 'warning', summary: 'Worker deployment exists, but artifact parity cannot be proved across every detected surface.', evidence: parity.evidence }
      return { status: 'pass', summary: 'Every detected web and worker deployment surface uses the same artifact.', evidence: parity.evidence }
    },
  }),
  rule({
    id: 'storage-persistent-volume', title: 'Local storage is placed on persistent media', category: 'Data', severity: 'high',
    remediation: 'Use durable object storage or mount every local upload/document path on persistent media and include it in recovery plans.',
    check: (context) => {
      const installed = dependencies(context)
      if (!installed.has('@open-mercato/documents') && !installed.has('@open-mercato/core')) return { status: 'skipped', summary: 'No storage-owning Open Mercato package was detected.' }
      const source = context.collectDeploymentText()
      return /(?:volume|storage|upload|s3)/i.test(source)
        ? { status: 'warning', summary: 'Storage configuration is present; verify durability, capacity alerts, and restore coverage in the live environment.' }
        : { status: 'fail', summary: 'No persistent storage configuration or runbook was found.' }
    },
  }),
  rule({
    id: 'data-backup-restore-runbook', title: 'Backups and restore rehearsal are documented', category: 'Data', severity: 'critical',
    remediation: 'Document database and file backups, retention, encryption, off-site copies, restore ownership, and a dated restore rehearsal.',
    check: (context) => {
      const source = context.collectDeploymentText()
      return containsAll(source.toLowerCase(), ['backup', 'restore'])
        ? { status: 'warning', summary: 'Backup and restore guidance exists; verify current off-site copies and a successful dated restore rehearsal.' }
        : { status: 'fail', summary: 'No backup-and-restore runbook was found.' }
    },
  }),
  rule({
    id: 'release-rollback-runbook', title: 'Rollback and forward-fix procedures are documented', category: 'Release', severity: 'high',
    remediation: 'Document immutable artifact rollback, database compatibility constraints, forward-fix ownership, and rollback verification.',
    check: (context) => /\brollback\b|\bforward[- ]fix\b/i.test(context.collectDeploymentText())
      ? { status: 'warning', summary: 'Rollback guidance exists; rehearse it against the actual provider and database change policy.' }
      : { status: 'fail', summary: 'No rollback or forward-fix runbook was found.' },
  }),
  rule({
    id: 'observability-telemetry-pipeline', title: 'Logs and telemetry have a production pipeline', category: 'Observability', severity: 'medium',
    remediation: 'Configure structured log collection plus an OTLP/APM backend, retention, alerts, and redaction checks.',
    check: (context) => {
      const inventory = templateInventory(context)
      const config = ['docker/otel-collector-config.yaml', 'docker/otel-collector-config.yml'].filter(context.exists)
      const hasSetting = [...inventory.names].some((key) => /^(?:OTEL_|NEW_RELIC_|SENTRY_)/.test(key))
      if (config.length && hasSetting) return { status: 'warning', summary: 'Telemetry configuration is present; verify live ingestion, alerts, retention, and redaction.', evidence: fileEvidence(config) }
      return { status: 'fail', summary: 'A production telemetry pipeline is not represented in the application configuration.' }
    },
  }),
  rule({
    id: 'runtime-supported-node', title: 'The app pins a supported Node.js runtime', category: 'Runtime', severity: 'medium',
    remediation: 'Declare Node.js 24 or newer in package.json and pin the same major in the deployment environment.',
    check: (context) => {
      const engines = context.packageJson.engines
      const node = engines && typeof engines === 'object' && !Array.isArray(engines) ? (engines as Record<string, unknown>).node : undefined
      return typeof node === 'string' && requiresNode24OrNewer(node)
        ? { status: 'pass', summary: 'package.json requires Node.js 24 or newer.', evidence: ['A supported Node.js engine constraint is declared.'] }
        : { status: 'fail', summary: 'package.json does not require a supported Node.js runtime.' }
    },
  }),
  rule({
    id: 'runtime-debug-features-disabled', title: 'Development-only features default off', category: 'Runtime', severity: 'high',
    remediation: 'Keep debug, profiling, autologin, test injection, and DevTools switches disabled in the production template.',
    check: (context) => {
      const inventory = templateInventory(context)
      const risky = [...inventory.booleans].filter(([, enabled]) => enabled).map(([key]) => key)
      return risky.length === 0
        ? { status: 'warning', summary: 'No development-only switch defaults to enabled in .env.example; verify the live environment separately.' }
        : { status: 'fail', summary: 'Development-only switches default to enabled.', evidence: risky.map((key) => `Enabled template switch: ${key}`) }
    },
  }),
] as const
