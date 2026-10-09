import { isLiveEnvPath } from './files.js'
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
  for (const line of source.split(/\r?\n/)) {
    const match = line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/)
    if (match?.[1] === undefined || match[2] === undefined) continue
    const key = match[1]
    const rawValue = match[2].trim()
    names.add(key)
    if (/(?:DEBUG|PROFILE|DEVTOOLS|AUTOLOGIN|TEST_INJECT|DEMO_MODE|EMERGENCY_BYPASS|INTEGRATION_TEST|AUTO_SPAWN_WORKERS)/.test(key)) {
      if (/^(?:1|true|yes|on)$/i.test(rawValue)) booleans.set(key, true)
      if (/^(?:0|false|no|off)$/i.test(rawValue)) booleans.set(key, false)
    }
    if (key === 'RATE_LIMIT_TRUST_PROXY_DEPTH' && /^-?\d+$/.test(rawValue)) integers.set(key, Number(rawValue))
    if (key === 'CACHE_STRATEGY' && /^(?:redis|memory|sqlite)$/i.test(rawValue)) enums.set(key, rawValue.toLowerCase())
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

function trackedCredentialPath(relativePath: string): boolean {
  const normalized = relativePath.replaceAll('\\', '/')
  const basename = normalized.split('/').at(-1)?.toLowerCase() ?? ''
  return /\.(?:pem|key|p12|pfx|jks)$/i.test(basename)
    || ['id_rsa', 'id_ed25519', '.mcp.json', '.npmrc'].includes(basename)
    || /(?:^|\/)\.(?:codex|cursor)\/mcp\.json$/i.test(normalized)
}

type ComposeService = { name: string, lines: string[] }

function composeServices(source: string): ComposeService[] {
  const services: ComposeService[] = []
  let servicesIndent: number | null = null
  let serviceIndent: number | null = null
  let current: ComposeService | null = null
  for (const line of source.split(/\r?\n/)) {
    const servicesMatch = line.match(/^(\s*)services:\s*(?:#.*)?$/)
    if (servicesMatch) {
      servicesIndent = servicesMatch[1]?.length ?? 0
      continue
    }
    if (servicesIndent === null) continue
    if (!line.trim() || /^\s*#/.test(line)) {
      if (current) current.lines.push(line)
      continue
    }
    const indent = line.length - line.trimStart().length
    if (indent <= servicesIndent) break
    const serviceMatch = line.match(/^(\s*)([A-Za-z0-9_.-]+):\s*(?:#.*)?$/)
    if (serviceIndent === null && serviceMatch?.[2]) serviceIndent = indent
    if (serviceMatch?.[2] && indent === serviceIndent) {
      if (current) services.push(current)
      current = { name: serviceMatch[2], lines: [] }
      continue
    }
    if (current) current.lines.push(line)
  }
  if (current && !services.includes(current)) services.push(current)
  return services
}

function isLoopbackBinding(value: string): boolean {
  const normalized = value.replace(/^['"]|['"]$/g, '').trim()
  return /^(?:127(?:\.\d{1,3}){3}|localhost):/i.test(normalized) || /^\[::1\]:/.test(normalized)
}

function inlinePortValues(value: string): string[] | null {
  const trimmed = value.trim()
  if (!trimmed.startsWith('[') || !trimmed.endsWith(']')) return null
  const body = trimmed.slice(1, -1).trim()
  if (!body) return []
  const values: string[] = []
  for (const part of body.split(',')) {
    const token = part.trim().replace(/^['"]|['"]$/g, '')
    if (!token || /[{}]/.test(token)) return null
    values.push(token)
  }
  return values
}

function servicePortFindings(file: string, service: ComposeService): string[] {
  const findings: string[] = []
  for (let index = 0; index < service.lines.length; index += 1) {
    const line = service.lines[index] ?? ''
    const ports = line.match(/^(\s*)ports:\s*(.*?)\s*(?:#.*)?$/)
    if (!ports) continue
    const portsIndent = ports[1]?.length ?? 0
    const inline = ports[2] ?? ''
    if (inline) {
      const values = inlinePortValues(inline)
      if (values === null) findings.push(`${file}: ${service.name} uses unsupported inline ports syntax`)
      else for (const binding of values) if (!isLoopbackBinding(binding)) findings.push(`${file}: ${service.name} publishes ${displayPath(binding)}`)
      continue
    }
    for (let nested = index + 1; nested < service.lines.length; nested += 1) {
      const nestedLine = service.lines[nested] ?? ''
      const indent = nestedLine.length - nestedLine.trimStart().length
      if (nestedLine.trim() && indent <= portsIndent) break
      const item = nestedLine.match(/^\s*-\s*(.*?)\s*(?:#.*)?$/)?.[1]
      if (item === undefined) continue
      if (/^target\s*:/.test(item)) {
        let hostIp = ''
        for (let field = nested; field < service.lines.length; field += 1) {
          const fieldLine = service.lines[field] ?? ''
          const fieldIndent = fieldLine.length - fieldLine.trimStart().length
          if (field > nested && fieldLine.trim() && fieldIndent <= indent) break
          const hostMatch = fieldLine.match(/^\s*host_ip\s*:\s*["']?([^\s"']+)/)
          if (hostMatch?.[1]) hostIp = hostMatch[1]
        }
        if (!/^(?:127(?:\.\d{1,3}){3}|localhost|::1)$/i.test(hostIp)) findings.push(`${file}: ${service.name} publishes a long-syntax port`)
        continue
      }
      if (!item || /[{}]/.test(item)) findings.push(`${file}: ${service.name} uses unsupported ports syntax`)
      else if (!isLoopbackBinding(item)) findings.push(`${file}: ${service.name} publishes ${displayPath(item)}`)
    }
  }
  return findings
}

function composePublicBindings(context: ScanContext): string[] {
  const findings: string[] = []
  for (const file of ['docker-compose.yml', 'docker-compose.fullapp.yml']) {
    const source = context.readText(file)
    if (!source) continue
    for (const service of composeServices(source)) {
      const body = service.lines.join('\n')
      if (!/(?:postgres|redis|search|opensearch|elastic|meili)/i.test(`${service.name}\n${body.match(/^\s*image:\s*(.*)$/mi)?.[1] ?? ''}`)) continue
      findings.push(...servicePortFindings(file, service))
    }
  }
  return findings
}

function workerDockerfiles(context: ScanContext): string[] {
  const values: string[] = []
  for (const file of ['railway.toml', 'railway.worker.toml']) {
    const source = context.readText(file)
    if (!source) continue
    const configured = source.match(/dockerfilePath\s*=\s*["']([^"']+)["']/i)?.[1]
    values.push(configured ? displayPath(configured) : 'Dockerfile')
  }
  return values
}

function finalDockerUser(source: string): string | null {
  const lines = source.split(/\r?\n/)
  let finalStageStart = -1
  for (let index = 0; index < lines.length; index += 1) {
    if (/^\s*FROM\s+/i.test(lines[index] ?? '')) finalStageStart = index
  }
  if (finalStageStart < 0) return null
  let user: string | null = null
  for (const line of lines.slice(finalStageStart + 1)) {
    const match = line.match(/^\s*USER\s+([^\s#]+)/i)
    if (match?.[1]) user = match[1].toLowerCase()
  }
  return user
}

type WorkflowCommand = { command: string, blocking: boolean }

function yamlFalse(value: string): boolean {
  return /^(?:false|['"]false['"]|\$\{\{\s*false\s*\}\})\s*$/i.test(value.trim())
}

function yamlTrue(value: string): boolean {
  return /^(?:true|['"]true['"]|\$\{\{\s*true\s*\}\})\s*$/i.test(value.trim())
}

function indentation(line: string): number {
  return line.length - line.trimStart().length
}

function workflowCommands(source: string): WorkflowCommand[] {
  const lines = source.split(/\r?\n/)
  const commands: WorkflowCommand[] = []
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? ''
    const runMatch = line.match(/^(\s*)(-\s*)?run:\s*(.*?)\s*$/)
    if (!runMatch) continue
    const runIndent = (runMatch[1]?.length ?? 0) + (runMatch[2]?.length ?? 0)
    let stepStart = index
    for (let previous = index; previous >= 0; previous -= 1) {
      const candidate = lines[previous] ?? ''
      const listMatch = candidate.match(/^(\s*)-\s+/)
      if (listMatch && (listMatch[1]?.length ?? 0) < runIndent) {
        stepStart = previous
        break
      }
    }
    const stepIndent = indentation(lines[stepStart] ?? '')
    let stepEnd = lines.length
    for (let candidate = stepStart + 1; candidate < lines.length; candidate += 1) {
      const candidateLine = lines[candidate] ?? ''
      if (!candidateLine.trim() || /^\s*#/.test(candidateLine)) continue
      const candidateIndent = indentation(candidateLine)
      if (candidateIndent < stepIndent || (candidateIndent === stepIndent && /^\s*-\s+/.test(candidateLine))) {
        stepEnd = candidate
        break
      }
    }
    let jobsStart = -1
    for (let previous = index; previous >= 0; previous -= 1) {
      if (/^\s*jobs:\s*(?:#.*)?$/.test(lines[previous] ?? '')) {
        jobsStart = previous
        break
      }
    }
    let jobStart = -1
    let jobEnd = lines.length
    let jobIndent: number | null = null
    let jobsIndent: number | null = null
    if (jobsStart >= 0) {
      jobsIndent = indentation(lines[jobsStart] ?? '')
      for (let candidate = jobsStart + 1; candidate <= index; candidate += 1) {
        const candidateLine = lines[candidate] ?? ''
        if (!candidateLine.trim() || /^\s*#/.test(candidateLine)) continue
        const candidateIndent = indentation(candidateLine)
        if (candidateIndent <= jobsIndent) break
        const key = candidateLine.match(/^\s*([A-Za-z0-9_.-]+):\s*(?:#.*)?$/)?.[1]
        if (jobIndent === null && key) jobIndent = candidateIndent
        if (key && candidateIndent === jobIndent) jobStart = candidate
      }
      if (jobStart >= 0 && jobIndent !== null) {
        for (let candidate = jobStart + 1; candidate < lines.length; candidate += 1) {
          const candidateLine = lines[candidate] ?? ''
          if (!candidateLine.trim() || /^\s*#/.test(candidateLine)) continue
          const candidateIndent = indentation(candidateLine)
          const key = candidateLine.match(/^\s*([A-Za-z0-9_.-]+):\s*(?:#.*)?$/)?.[1]
          if (candidateIndent <= jobsIndent || (key && candidateIndent === jobIndent)) {
            jobEnd = candidate
            break
          }
        }
      }
    }
    const stepLines = lines.slice(stepStart, stepEnd)
    const stepFieldIndent = stepLines.reduce<number | null>((minimum, candidate, offset) => {
      if (offset === 0 || !candidate.trim() || /^\s*#/.test(candidate)) return minimum
      const candidateIndent = indentation(candidate)
      if (candidateIndent <= stepIndent) return minimum
      return minimum === null ? candidateIndent : Math.min(minimum, candidateIndent)
    }, null)
    const stepControl = stepLines.filter((candidate, offset) => offset === 0 || (stepFieldIndent !== null && indentation(candidate) === stepFieldIndent))
    const jobLines = jobStart >= 0 ? lines.slice(jobStart + 1, jobEnd) : []
    const jobFieldIndent = jobIndent === null
      ? null
      : jobLines.reduce<number | null>((minimum, candidate) => {
        if (!candidate.trim() || /^\s*#/.test(candidate)) return minimum
        const candidateIndent = indentation(candidate)
        if (candidateIndent <= jobIndent) return minimum
        return minimum === null ? candidateIndent : Math.min(minimum, candidateIndent)
      }, null)
    const jobControl = jobFieldIndent === null ? [] : jobLines.filter((candidate) => indentation(candidate) === jobFieldIndent)
    const disabled = [...stepControl, ...jobControl].some((candidate) => {
      const condition = candidate.match(/^\s*(?:-\s*)?if:\s*(.*?)\s*(?:#.*)?$/)?.[1]
      return condition !== undefined && yamlFalse(condition)
    })
    const nonBlocking = [...stepControl, ...jobControl].some((candidate) => {
      const value = candidate.match(/^\s*(?:-\s*)?continue-on-error:\s*(.*?)\s*(?:#.*)?$/i)?.[1]
      return value !== undefined && yamlTrue(value)
    })
    let command = runMatch[3] ?? ''
    if (/^[|>][-+]?\s*$/.test(command)) {
      const block: string[] = []
      for (let nested = index + 1; nested < lines.length; nested += 1) {
        const nestedLine = lines[nested] ?? ''
        const indent = nestedLine.length - nestedLine.trimStart().length
        if (nestedLine.trim() && indent <= runIndent) break
        if (!/^\s*#/.test(nestedLine)) block.push(nestedLine.trim())
      }
      command = block.join('\n')
    }
    command = command.replace(/^['"]|['"]$/g, '')
    if (!disabled && command) commands.push({ command, blocking: !nonBlocking })
  }
  return commands
}

function hasBlockingPackageCommand(commands: WorkflowCommand[], name: string): boolean {
  const pattern = new RegExp(`(?:^|[;&|]\\s*)(?:corepack\\s+)?(?:yarn(?:\\s+run)?|pnpm(?:\\s+run)?|npm(?:\\s+run)?)\\s+${name}\\b`, 'im')
  return commands.some(({ command, blocking }) => blocking && pattern.test(command))
}

function hasBlockingMigrationCommand(commands: WorkflowCommand[]): boolean {
  return commands.some(({ command, blocking }) => blocking && /(?:^|[;&|]\s*)(?:yarn|pnpm|npm(?:\s+run)?)\s+(?:db:migrate|mercato\s+db\s+migrate)\b/im.test(command))
}

function requiresNode24OrNewer(range: string): boolean {
  const clauses = range.split('||').map((clause) => clause.trim()).filter(Boolean)
  if (!clauses.length) return false
  return clauses.every((clause) => {
    const hyphen = clause.match(/^v?(\d+)(?:\.(?:\d+|[x*])){0,2}(?:-[0-9A-Za-z.-]+)?\s+-\s+v?\d+(?:\.(?:\d+|[x*])){0,2}(?:-[0-9A-Za-z.-]+)?$/i)
    if (hyphen?.[1]) return Number(hyphen[1]) >= 24
    const normalized = clause.replace(/(<=|>=|<|>|=|\^|~)\s+/g, '$1')
    const tokens = normalized.split(/\s+/).filter(Boolean)
    let strongestLowerMajor: number | null = null
    let exactMajor: number | null = null
    for (const token of tokens) {
      if (token === '*' || /^x$/i.test(token)) return false
      const match = token.match(/^(<=|>=|<|>|=|\^|~)?v?(\d+)(?:\.(?:\d+|[x*])){0,2}(?:-[0-9A-Za-z.-]+)?$/i)
      if (!match?.[2]) return false
      const operator = match[1] ?? '='
      const major = Number(match[2])
      if (operator === '<' || operator === '<=') continue
      if (operator === '=') {
        if (exactMajor !== null && exactMajor !== major) return false
        exactMajor = major
      }
      if (operator === '>' && major < 24) continue
      strongestLowerMajor = strongestLowerMajor === null ? major : Math.max(strongestLowerMajor, major)
    }
    if (exactMajor !== null && exactMajor < 24) return false
    return strongestLowerMajor !== null && strongestLowerMajor >= 24
  })
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
      const tracked = [...context.trackedFiles].filter(trackedCredentialPath)
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
      if (!/NODE_ENV=production/.test(values.build ?? '')) return { status: 'fail', summary: 'The build script does not explicitly force NODE_ENV=production.' }
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
      const source = context.readText('next.config.ts') ?? context.readText('next.config.mjs') ?? ''
      const required = ['Content-Security-Policy', 'Referrer-Policy', 'X-Content-Type-Options']
      const missing = required.filter((header) => !source.includes(header))
      if (!/X-Frame-Options|frame-ancestors/.test(source)) missing.push('frame protection')
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
    check: (context) => /yarn\s+install\s+--immutable|npm\s+ci\b|pnpm\s+install\s+--frozen-lockfile/i.test(context.collectDeploymentText())
      ? { status: 'pass', summary: 'Deployment configuration uses an immutable dependency install.' }
      : { status: 'fail', summary: 'No immutable dependency installation was found in deployment configuration.' },
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
      const hasWorker = ['railway.worker.toml', 'scripts/railway-worker.sh'].some(context.exists)
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
    check: (context) => /(?:db[: ]migrate|mercato\s+db\s+migrate)/i.test(context.collectDeploymentText())
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
      const paths = ['railway.worker.toml', 'scripts/railway-worker.sh', 'docker-compose.fullapp.yml'].filter(context.exists)
      return paths.length
        ? { status: 'pass', summary: 'An explicit worker deployment surface is present.', evidence: fileEvidence(paths) }
        : { status: 'fail', summary: 'The queue package is installed but no worker deployment surface was found.' }
    },
  }),
  rule({
    id: 'workers-release-parity', title: 'Web and worker processes use the same release artifact', category: 'Operations', severity: 'high',
    remediation: 'Deploy one immutable build to web and worker roles and vary only the supported entrypoint.',
    check: (context) => {
      if (!context.exists('railway.worker.toml') && !context.exists('scripts/railway-worker.sh')) return { status: 'skipped', summary: 'No separate worker process was detected.' }
      const dockerfiles = workerDockerfiles(context)
      if (dockerfiles.length < 2) return { status: 'warning', summary: 'Worker deployment exists, but artifact parity is controlled outside recognized repository files.' }
      return new Set(dockerfiles).size === 1
        ? { status: 'pass', summary: 'Web and worker deployment definitions use the same Dockerfile.', evidence: [`Shared build definition: ${dockerfiles[0]}`] }
        : { status: 'fail', summary: 'Web and worker deployment definitions use different build artifacts.', evidence: dockerfiles.map((file) => `Build definition: ${file}`) }
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
