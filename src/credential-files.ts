import fs from 'node:fs'
import path from 'node:path'
import { parseEnv } from 'node:util'
import { parse } from 'yaml'
import { assessCredentials, credentialKind, SECRET_DELIVERY_GUIDANCE } from './credentials.js'
import type { CredentialAssessment } from './credentials.js'
import type { RuleCheck } from './types.js'

export const PRODUCTION_ENV_FILES = ['.env', '.env.production', '.env.local', '.env.production.local'] as const
const MAX_BYTES = 1_048_576
const TEMPLATES = ['.env.example', '.env.sample', '.env.template'] as const
const COMPOSE_FILES = ['docker-compose.yml', 'docker-compose.yaml', 'docker-compose.fullapp.yml', 'compose.yml', 'compose.yaml'] as const
export type CredentialInspection = CredentialAssessment & { delivery: RuleCheck }

function readBoundedFile(root: string, file: string): string | null {
  let descriptor: number | undefined
  const buffer = Buffer.alloc(MAX_BYTES + 1)
  try {
    const absolute = path.join(root, file)
    const before = fs.lstatSync(absolute)
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > MAX_BYTES) return null
    descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0))
    const stat = fs.fstatSync(descriptor)
    if (!stat.isFile() || stat.nlink !== 1 || stat.dev !== before.dev || stat.ino !== before.ino || stat.size > MAX_BYTES) return null
    let length = 0
    while (length <= MAX_BYTES) {
      const read = fs.readSync(descriptor, buffer, length, buffer.length - length, null)
      if (!read) break
      length += read
    }
    return length > MAX_BYTES ? null : buffer.toString('utf8', 0, length)
  } catch { return null }
  finally { buffer.fill(0); if (descriptor !== undefined) fs.closeSync(descriptor) }
}

function combine(checks: RuleCheck[], fallback: string): RuleCheck {
  checks = checks.filter((check) => check.status !== 'skipped')
  const primary = checks.find((check) => check.status === 'fail') ?? checks.find((check) => check.status === 'warning') ?? checks[0]
  return { status: primary?.status ?? 'warning', summary: primary?.summary ?? fallback, evidence: [...new Set(checks.flatMap((check) => check.evidence ?? []))].sort() }
}

/** The bounded live dotenv reader. Enabled for scan; apply explicitly disables it. */
export function inspectLocalCredentials(root: string, enabled = true, environment: Readonly<Record<string, string | undefined>> = process.env): CredentialInspection {
  const present = PRODUCTION_ENV_FILES.filter((file) => { try { fs.lstatSync(path.join(root, file)); return true } catch { return false } })
  const delivery: RuleCheck = {
    status: 'warning', summary: present.length ? 'Local production environment files exist. Keep them out of deployed artifacts and inject production credentials through a secret mechanism.' : 'Verify that production credentials are injected through the hosting platform secret mechanism.',
    evidence: present.map((file) => `Local environment path: ${file}`),
  }
  if (!enabled) return {
    credentials: { status: 'skipped', summary: 'Live credential strength was not inspected. Run scan to inspect local production settings in memory.' },
    encryption: { status: 'skipped', summary: 'Live encryption key strength was not inspected. Run scan to inspect local production settings in memory.' },
    kms: { status: 'warning', summary: `KMS configuration is unverified because live credential inspection is disabled. ${SECRET_DELIVERY_GUIDANCE}` }, delivery,
  }
  const templates: Record<string, string[]> = Object.create(null)
  for (const file of TEMPLATES) {
    const source = readBoundedFile(root, file)
    if (source === null) continue
    try { for (const [name, value] of Object.entries(parseEnv(source))) { if (value !== undefined) (templates[name] ??= []).push(value) } }
    catch { /* Never echo parser errors or source values. */ }
  }
  const assessments: CredentialAssessment[] = []
  const missing: string[] = []
  const effective: Record<string, string | undefined> = Object.create(null)
  const assess = (settings: Record<string, string | undefined>, label: string): void => {
    const assessment = assessCredentials(settings, templates)
    for (const key of ['credentials', 'encryption'] as const) assessment[key].evidence = (assessment[key].evidence ?? []).map((entry) => `${label}: ${entry}`)
    assessments.push(assessment)
  }
  for (const file of present) {
    const source = readBoundedFile(root, file)
    if (source === null) { missing.push(`${file}: not inspected (unreadable, linked, non-regular, or oversized file).`); continue }
    try { const settings = parseEnv(source); Object.assign(effective, settings); assess(settings, file) }
    catch { missing.push(`${file}: dotenv settings could not be safely parsed.`) }
  }
  for (const file of COMPOSE_FILES) {
    const source = readBoundedFile(root, file)
    if (source === null) continue
    try {
      const document: unknown = parse(source, { merge: true, maxAliasCount: 100 })
      if (!document || typeof document !== 'object' || !('services' in document) || !document.services || typeof document.services !== 'object') continue
      for (const service of Object.values(document.services)) {
        if (!service || typeof service !== 'object') continue
        const settings: Record<string, string | undefined> = Object.create(null)
        if ('environment' in service && service.environment && typeof service.environment === 'object') {
          if (Array.isArray(service.environment)) {
            for (const entry of service.environment) { if (typeof entry === 'string') { const separator = entry.indexOf('='); if (separator >= 0) settings[entry.slice(0, separator)] = entry.slice(separator + 1); else if (credentialKind(entry)) { if (environment[entry] !== undefined) settings[entry] = environment[entry]; else missing.push(`${file}: inherited service credential is unavailable for inspection.`) } } }
          } else { for (const [name, value] of Object.entries(service.environment)) { if (typeof value === 'string' || typeof value === 'number') settings[name] = String(value); else if (credentialKind(name)) { if (value === null && environment[name] !== undefined) settings[name] = environment[name]; else missing.push(`${file}: service credential is inherited, missing, or not a string.`) } } }
        }
        if ('command' in service) {
          const command = service.command
          if (Array.isArray(command)) { const index = command.indexOf('--requirepass'); if (index >= 0 && typeof command[index + 1] === 'string') settings.REDIS_PASSWORD = command[index + 1] }
          else if (typeof command === 'string') { const match = command.match(/--requirepass(?:=|\s+)(?:"([^"]*)"|'([^']*)'|([^\s]+))/); if (match) settings.REDIS_PASSWORD = match[1] ?? match[2] ?? match[3] }
        }
        if ('env_file' in service) missing.push(`${file}: service env_file references are not followed; inspect injected service credentials separately.`)
        assess(settings, file)
      }
    } catch { missing.push(`${file}: service credentials could not be safely parsed.`) }
  }
  const runtime: Record<string, string | undefined> = Object.create(null)
  const configurationKeys = new Set(['VAULT_ADDR', 'VAULT_TOKEN', 'TENANT_DATA_ENCRYPTION', 'ALLOW_DERIVED_KMS_FALLBACK'])
  for (const name of Object.keys(environment).sort()) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name)) continue
    if (credentialKind(name) || configurationKeys.has(name) || /(?:URL|URI|DSN|CONNECTION_STRING)$/i.test(name)) runtime[name] = environment[name]
  }
  Object.assign(effective, runtime)
  if (Object.keys(runtime).length) assess(runtime, 'Runtime environment')
  const effectiveKms = assessCredentials(effective, templates).kms
  const kms = effectiveKms.summary.startsWith('Vault KMS settings are present') ? effectiveKms : assessments.find((assessment) => assessment.kms.summary.startsWith('Vault KMS settings are present'))?.kms ?? effectiveKms
  const credentials = combine(assessments.map((assessment) => assessment.credentials), 'No local credentials were available to assess; verify deployment-injected secrets.')
  const encryption = combine(assessments.map((assessment) => assessment.encryption), 'No local encryption keys were available to assess; verify deployment-injected keys.')
  const coverage = [...missing]
  if (!effective.JWT_SECRET?.trim()) coverage.push('JWT_SECRET: not available in inspected settings; verify the deployed signing secret.')
  if (!Object.keys(effective).some((name) => /(?:DATABASE_URL|PGPASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD|DB_PASSWORD|DATABASE_PASSWORD)$/i.test(name) && effective[name]?.trim())) coverage.push('Database credentials: not available in inspected settings; verify deployed authentication.')
  if (coverage.length) {
    if (credentials.status !== 'fail') { credentials.status = 'warning'; credentials.summary = 'Credential inspection is incomplete; verify the settings supplied at deployment.' }
    credentials.evidence = [...new Set([...(credentials.evidence ?? []), ...coverage])].sort()
    if (missing.length && encryption.status !== 'fail') { encryption.status = 'warning'; encryption.summary = 'Encryption key inspection is incomplete; some production configuration was not inspected.'; encryption.evidence = [...new Set([...(encryption.evidence ?? []), ...missing])].sort() }
  }
  return { credentials, encryption, kms, delivery }
}
