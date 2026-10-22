import type { RuleCheck } from './types.js'

export type CredentialAssessment = { credentials: RuleCheck, encryption: RuleCheck, kms: RuleCheck }
export type CredentialTemplates = Readonly<Record<string, string | readonly string[] | undefined>>
type Kind = 'password' | 'signing' | 'encryption' | 'token'
type Problem = { name: string, reason: string, review: boolean, encryption: boolean }

const ENCRYPTION_KEYS = new Set(['TENANT_DATA_ENCRYPTION_FALLBACK_KEY', 'TENANT_DATA_ENCRYPTION_KEY', 'KMS_MASTER_KEY', 'FORMS_ENCRYPTION_MASTER_KEY', 'LOOKUP_HASH_PEPPER'])
const DEFAULTS = new Set(['jwt', 'jwt-secret', 'jwtsecret', 'secret', 'password', 'password123', 'admin', 'admin123', 'root', 'guest', 'postgres', 'mysql', 'redis', 'changeme', 'change-me', 'dev', 'development', 'test', 'example', 'placeholder', 'dummy', 'default', 'correct horse battery staple', 'om-dev-tenant-encryption', 'dev-tenant-encryption-fallback-key-32chars', 'wjalrxutnfemi/k7mdeng/bpxrficyexamplekey'])
const VALID_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/
const REFERENCE = /^\$(?:\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*)$/
export const SECRET_DELIVERY_GUIDANCE = 'Without KMS, inject strong, durable encryption keys through Railway or Cloudflare secrets, or GitHub Actions secrets during deployment. Do not deploy keys in plaintext .env files. Retain keys securely for recovery; changing an existing key can make encrypted data unreadable.'

function normalizedName(name: string): string {
  return name.replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase()
}

/** Classify names without treating public identifiers, paths, limits, and toggles as secrets. */
export function credentialKind(name: string): Kind | null {
  const key = normalizedName(name)
  if (/(?:^|_)(?:PUBLIC|PUBLISHABLE)(?:_|$)/.test(key)
    || /(?:_FILE|_PATH|_NAME|_ID|_ARN|_URL|_URI|_ENDPOINT|_PREFIX|_SUFFIX|_LENGTH|_SIZE|_TTL|_TIMEOUT|_INTERVAL|_MINUTES|_SECONDS|_DAYS|_ENABLED|_DISABLED|_DEBUG|_MODE|_FORMAT|_VERSION|_MAX|_MIN|_COUNT|_LIMIT|_EXPIRES(?:_IN)?|_DURATION|_ALGORITHM|_ALG|_REQUIRED|_OPTIONAL|_MAX_AGE)$/.test(key)
    || /(?:^|_)(?:MAX|MIN|STORE|ALLOW|ENABLE|DISABLE|REQUIRE|USE|GENERATE)(?:_|$)/.test(key)
    || /(?:TOKENS|TOKENIZER)(?:_|$)/.test(key)) return null
  if (ENCRYPTION_KEYS.has(key) || /(?:ENCRYPTION|CIPHER|KMS|CRYPT).*(?:KEY|SECRET)$/.test(key)) return 'encryption'
  if (/(?:PASSWORD|PASSWD|PASSPHRASE|PGPASSWORD|(?:^|_)(?:PWD|PASS)$)/.test(key)) return 'password'
  if (/(?:JWT|AUTH|SESSION|SIGNING|WEBHOOK|OAUTH_STATE|THREAD_TOKEN).*(?:SECRET|KEY)(?:_V?\d+)?$/.test(key)) return 'signing'
  if (/(?:SECRET|TOKEN|API_?KEY|(?:ACCESS|MASTER|SERVICE|CLIENT|PRIVATE)_KEY|CREDENTIALS?|PEPPER|REDISCLI_AUTH)(?:_|$)/.test(key)) return 'token'
  return null
}

function placeholder(value: string): boolean {
  return DEFAULTS.has(value.toLowerCase()) || /^<[^>]*>$/.test(value)
    || /change[-_ ]?me|replace[-_ ]?(?:me|with)|your[-_ ](?:.*(?:key|secret|password|token)|credential)/i.test(value)
    || /(?:^|[-_ ])(?:dev|development|demo|test|example|placeholder|dummy|default)(?:[-_ ]|$)/i.test(value)
    || /^(?:x+|\*+|\.{3}|tbd|todo|null|undefined|none|not[-_ ]?set)$/i.test(value)
}

function repeated(value: string): boolean {
  for (let length = 1; length <= Math.min(16, Math.floor(value.length / 2)); length += 1) {
    if (value === value.slice(0, length).repeat(Math.ceil(value.length / length)).slice(0, value.length)) return true
  }
  return new Set(value).size < 6
}

function keyBytes(value: string): Buffer {
  if (/^(?:hex:)?[a-f\d]+$/i.test(value) && value.replace(/^hex:/i, '').length % 2 === 0) return Buffer.from(value.replace(/^hex:/i, ''), 'hex')
  const base64 = value.replace(/^base64:/i, '')
  if (/^base64:/i.test(value) || (/^[A-Za-z\d+/_-]+={0,2}$/.test(value) && (/[+/=_-]/.test(value) || base64.length === 43 || base64.length === 44))) {
    const decoded = Buffer.from(base64, 'base64')
    if (decoded.toString('base64url') === base64.replace(/=+$/, '').replaceAll('+', '-').replaceAll('/', '_')) return decoded
  }
  return Buffer.from(value, 'utf8')
}

function templateValues(value: string | readonly string[] | undefined): readonly string[] {
  return typeof value === 'string' ? [value] : value ?? []
}

function weakness(value: string, kind: Kind, templates: readonly string[], username?: string): { reason: string, review: boolean } | null {
  const fallback = value.match(/^\$\{[A-Za-z_][A-Za-z0-9_]*(?::-|-)(.*?)\}$/)?.[1]
  if (fallback !== undefined) {
    const problem = weakness(fallback, kind, templates, username)
    if (problem && !problem.review) return { reason: `secret reference has an unsafe fallback: ${problem.reason}`, review: false }
  }
  if (REFERENCE.test(value) || /^(?:secret|vault|kms):\/\//i.test(value)) return { reason: 'unresolved secret reference requires deployment verification', review: true }
  if (!value) return { reason: 'credential is empty', review: false }
  if (placeholder(value) || (username && value.toLowerCase() === username.toLowerCase())) return { reason: 'uses a known default or template placeholder', review: false }
  if (templates.some((template) => template.trim() && value === template.trim())) return { reason: 'matches a credential published in the application template', review: false }
  if (value.includes('-----BEGIN ')) return { reason: 'embedded key material needs separate algorithm and key-size verification', review: true }
  if (/^[A-Za-z\d_-]+\.[A-Za-z\d_-]*\.[A-Za-z\d_-]*$/.test(value)) {
    try {
      const header: unknown = JSON.parse(Buffer.from(value.split('.')[0] ?? '', 'base64url').toString('utf8'))
      if (header && typeof header === 'object' && 'alg' in header && typeof header.alg === 'string' && header.alg.toLowerCase() === 'none') return { reason: 'JWT declares an unsigned algorithm', review: false }
      return { reason: 'JWT signature, issuer, audience, and expiry require separate verification', review: true }
    } catch { return { reason: 'JWT header cannot be safely parsed', review: true } }
  }
  if (kind === 'password' && [...value].length < 16) return { reason: 'below the 16-character minimum for passwords', review: false }
  const minimum = kind === 'encryption' || kind === 'signing' ? 32 : 16
  const bytes = kind === 'encryption' || kind === 'signing' ? keyBytes(value) : Buffer.from(value, 'utf8')
  if (bytes.length < minimum) return { reason: `below the ${minimum}-byte minimum for this credential type`, review: false }
  if (repeated(value) || ((kind === 'encryption' || kind === 'signing') && new Set(bytes).size < 8)) return { reason: 'uses a repeated or low-diversity pattern', review: false }
  if (/^(?:0123456789|1234567890|abcdefghijklmnopqrstuvwxyz|qwertyuiop)/i.test(value)) return { reason: 'uses a predictable sequence', review: false }
  return null
}

function templatePasswords(value: string | readonly string[] | undefined): string[] {
  return templateValues(value).flatMap((entry) => {
    try { const password = decodeURIComponent(new URL(entry).password); return password ? [password] : [] } catch { return [] }
  })
}

/** Pure assessment. Only fixed reasons and validated names can enter the returned findings. */
export function assessCredentials(settings: Readonly<Record<string, string | undefined>>, templates: CredentialTemplates = {}): CredentialAssessment {
  const problems: Problem[] = []
  let checked = 0
  let encryptionChecked = 0
  const review = (name: string, reason: string): void => { problems.push({ name, reason, encryption: false, review: true }) }
  const inspect = (name: string, value: string, kind: Kind, template: readonly string[] = [], username?: string): void => {
    checked += 1
    if (kind === 'encryption') encryptionChecked += 1
    const result = weakness(value.trim(), kind, template, username)
    if (result) problems.push({ name, ...result, encryption: kind === 'encryption' })
  }
  for (const name of Object.keys(settings).sort()) {
    if (!VALID_NAME.test(name)) continue
    const value = settings[name]
    if (value === undefined) continue
    const kind = credentialKind(name)
    if (kind && value.trim()) {
      const defaults = templateValues(templates[name])
      if (defaults.some((template) => template.trim() && value.trim() === template.trim())) { inspect(name, value, kind, defaults); continue }
      if (/(?:CREDENTIALS?)$/i.test(name) && /^(?:\/|~\/|\.\.?\/)/.test(value)) { review(name, 'credential-file reference is not followed; verify it separately'); continue }
      if (/(?:CREDENTIALS?|AUTH_CONFIG)$/i.test(name) && value.trim().startsWith('{')) {
        let visited = 0
        const before = checked
        const visit = (entry: unknown, depth: number): void => {
          if (!entry || typeof entry !== 'object') return
          if (depth > 6 || visited > 1000) { review(name, 'credential object exceeds inspection bounds'); return }
          for (const [field, nested] of Object.entries(entry)) {
            if (++visited > 1000) { review(name, 'credential object exceeds inspection bounds'); break }
            const nestedKind = credentialKind(field)
            if (nestedKind && typeof nested === 'string') inspect(name, nested, nestedKind)
            else if (nested && typeof nested === 'object') visit(nested, depth + 1)
          }
        }
        try { visit(JSON.parse(value), 0); if (checked === before) review(name, 'credential object has no assessable credential fields') }
        catch { review(name, 'credential object could not be safely inspected') }
      } else inspect(name, value, kind, defaults)
      continue
    }
    if (!value.trim() && /^(?:JWT_SECRET|PGPASSWORD|POSTGRES_PASSWORD|MYSQL_(?:ROOT_)?PASSWORD|DB_PASSWORD|DATABASE_PASSWORD)$/.test(normalizedName(name))) inspect(name, value, kind ?? 'password')
    if (REFERENCE.test(value.trim()) && /(?:URL|URI|DSN|CONNECTION_STRING)$/i.test(name)) { review(name, 'connection credentials require deployment verification'); continue }
    try {
      const url = new URL(value)
      if (url.username || url.password) inspect(name, decodeURIComponent(url.password), 'password', templatePasswords(templates[name]), decodeURIComponent(url.username))
      else if (/^(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqps?|smtps?):$/.test(url.protocol)) review(name, 'service URL has no password; verify external authentication')
      for (const [key, parameter] of [...url.searchParams, ...new URLSearchParams(url.hash.replace(/^#/, ''))]) {
        const parameterKind = credentialKind(key)
        if (parameterKind) inspect(name, parameter, parameterKind)
      }
    } catch {
      if (/(?:URL|URI|DSN|CONNECTION_STRING)$/i.test(name)) {
        const passwords = [...value.matchAll(/(?:^|[;\s])(?:password|pwd)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^;\s]*))/gi)]
        if (passwords.length) for (const match of passwords) inspect(name, match[1] ?? match[2] ?? match[3] ?? '', 'password')
        else if (value.trim()) review(name, 'connection credentials could not be safely inspected')
      }
    }
  }
  if (/^(?:1|true|yes|on|enabled)$/i.test(settings.ALLOW_DERIVED_KMS_FALLBACK?.trim() ?? '') && !settings.TENANT_DATA_ENCRYPTION_FALLBACK_KEY?.trim() && !settings.TENANT_DATA_ENCRYPTION_KEY?.trim()) problems.push({ name: 'ALLOW_DERIVED_KMS_FALLBACK', reason: 'permits the published development encryption key outside production', encryption: true, review: false })
  if (/^(?:0|false|no|off|disabled)$/i.test(settings.TENANT_DATA_ENCRYPTION?.trim() ?? '')) problems.push({ name: 'TENANT_DATA_ENCRYPTION', reason: 'tenant data encryption is explicitly disabled', encryption: true, review: false })
  const result = (encryption: boolean): RuleCheck => {
    const relevant = problems.filter((problem) => problem.encryption === encryption)
    const failed = relevant.some((problem) => !problem.review)
    const count = encryption ? encryptionChecked : checked - encryptionChecked
    return {
      status: failed ? 'fail' : relevant.length ? 'warning' : !count ? 'skipped' : 'pass',
      summary: failed ? encryption ? 'Encryption keys include unsafe defaults, weak values, or disabled encryption.' : 'Credentials include unsafe defaults, template values, or weak values.'
        : relevant.length || !count ? encryption ? 'Encryption key strength requires operator verification.' : 'Credential coverage requires operator verification.'
          : encryption ? 'Inspected encryption keys meet the local static policy; randomness and deployment remain unverified.' : 'Inspected credentials meet the local static policy; validity and deployment remain unverified.',
      evidence: [...new Set(relevant.map(({ name, reason }) => `${name}: ${reason}.`))].sort(),
    }
  }
  let vaultAddress = false
  try { vaultAddress = /^https?:$/.test(new URL(settings.VAULT_ADDR ?? '').protocol) } catch { /* No configured HTTP Vault address. */ }
  const vaultConfigured = Boolean(vaultAddress && settings.VAULT_TOKEN?.trim() && !placeholder(settings.VAULT_TOKEN.trim()) && !REFERENCE.test(settings.VAULT_TOKEN.trim()))
  return {
    credentials: result(false), encryption: result(true),
    kms: { status: 'warning', summary: vaultConfigured ? 'Vault KMS settings are present; verify live access, key custody, recovery, and rotation.' : `No complete Vault KMS configuration was found in the inspected settings. ${SECRET_DELIVERY_GUIDANCE}` },
  }
}
