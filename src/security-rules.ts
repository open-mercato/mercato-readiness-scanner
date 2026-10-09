import { booleanSetting, weakSecret } from './environment.js'
import { PRODUCTION_ENV_FILES } from './files.js'
import type { RuleCheck, RuleDefinition } from './types.js'

function define(input: Omit<RuleDefinition, 'docsUrl'>): RuleDefinition {
  return { ...input, docsUrl: `https://github.com/open-mercato/mercato-readiness-scanner/blob/main/docs/rules/${input.id}.md` }
}

function problems(names: string[], summary: string): RuleCheck {
  return names.length
    ? { status: 'fail', summary, evidence: [...new Set(names)].sort().map((name) => `Review setting: ${name}`) }
    : { status: 'pass', summary: 'The inspected configuration meets this rule; live service behavior was not probed.' }
}

function credentialUrl(value: string | undefined, protocols: string[], separatePassword?: string): boolean {
  try {
    const url = new URL(value ?? '')
    decodeURIComponent(url.username)
    if (!protocols.includes(url.protocol) || !url.hostname || /\$\{|[<>]/.test(value ?? '')) return false
    return !weakSecret(decodeURIComponent(url.password) || separatePassword, 16)
  } catch { return false }
}

export const SECURITY_RULES: readonly RuleDefinition[] = [
  define({
    id: 'secrets-jwt-signing', title: 'Signing secrets resist known weak defaults', category: 'Secrets', severity: 'critical',
    remediation: 'Set JWT_SECRET to a unique random value of at least 32 characters. Set optional signing-secret overrides to equally strong independent values.',
    check: ({ environment }) => {
      const names = new Set(['JWT_SECRET', ...[...environment.values.keys()].filter((key) => /(?:JWT_SECRET(?:_[A-Z0-9_]+)?|AUTH_SECRET|NEXTAUTH_SECRET)$/.test(key))])
      const invalid = [...names].filter((key) => key === 'JWT_SECRET' || Boolean(environment.values.get(key))).filter((key) => weakSecret(environment.values.get(key)))
      return problems(invalid, 'Signing secrets are missing, short, repetitive, unresolved, or known placeholders.')
    },
  }),
  define({
    id: 'data-tenant-encryption-enabled', title: 'Tenant database field encryption is enabled', category: 'Data', severity: 'critical',
    remediation: 'Explicitly set TENANT_DATA_ENCRYPTION=yes and verify encryption maps and backfill completion. Provider disk encryption and database TLS require separate verification.',
    check: ({ environment }) => problems(booleanSetting(environment.values.get('TENANT_DATA_ENCRYPTION')) === true ? [] : ['TENANT_DATA_ENCRYPTION'], 'Tenant field encryption is disabled, missing, or invalid.'),
  }),
  define({
    id: 'data-encryption-key-config', title: 'Encryption has an independent fallback key', category: 'Data', severity: 'critical',
    remediation: 'Set TENANT_DATA_ENCRYPTION_FALLBACK_KEY (or TENANT_DATA_ENCRYPTION_KEY) to a unique random value of at least 32 characters, distinct from signing secrets. Back it up securely and verify Vault/KMS separately.',
    check: ({ environment }) => {
      const name = environment.values.get('TENANT_DATA_ENCRYPTION_FALLBACK_KEY')?.trim() ? 'TENANT_DATA_ENCRYPTION_FALLBACK_KEY' : 'TENANT_DATA_ENCRYPTION_KEY'
      const key = environment.values.get(name)
      const invalid = weakSecret(key) || ['JWT_SECRET', 'AUTH_SECRET', 'NEXTAUTH_SECRET'].some((setting) => key && key === environment.values.get(setting))
      const issues = invalid ? [name] : []
      if (booleanSetting(environment.values.get('ALLOW_DERIVED_KMS_FALLBACK')) === true) issues.push('ALLOW_DERIVED_KMS_FALLBACK')
      return problems(issues, 'Encryption fallback material is missing, weak, reused, or permits the development fallback.')
    },
  }),
  define({
    id: 'services-postgres-credentials', title: 'PostgreSQL uses explicit non-default credentials', category: 'Services', severity: 'critical',
    remediation: 'Set DATABASE_URL with a dedicated database role and a strong unique password. Disable trust authentication and resolve substitutions. Verify least privilege and database TLS separately.',
    check: ({ environment }) => {
      const values = environment.values
      const issues = credentialUrl(values.get('DATABASE_URL'), ['postgres:', 'postgresql:']) ? [] : ['DATABASE_URL']
      if (values.get('POSTGRES_HOST_AUTH_METHOD')?.toLowerCase() === 'trust') issues.push('POSTGRES_HOST_AUTH_METHOD')
      if (values.has('POSTGRES_PASSWORD') && weakSecret(values.get('POSTGRES_PASSWORD'), 16)) issues.push('POSTGRES_PASSWORD')
      const outcome = problems(issues, 'PostgreSQL credentials are missing, weak, malformed, or allow trust authentication.')
      if (outcome.status === 'pass') {
        const user = decodeURIComponent(new URL(values.get('DATABASE_URL') ?? '').username)
        if (!user) return problems(['DATABASE_URL'], 'The PostgreSQL connection has no explicit database role.')
        if (/^(?:postgres|root|admin)$/i.test(user)) return { status: 'warning', summary: 'The PostgreSQL URL selects a conventional administrator role; verify least privilege.', evidence: ['Review setting: DATABASE_URL'] }
      }
      return outcome
    },
  }),
  define({
    id: 'services-redis-credentials', title: 'Redis connections require authentication', category: 'Services', severity: 'high',
    remediation: 'Set authenticated Redis URLs for every cache, event, queue, and collaboration connection. Use strong unique passwords or ACL credentials, private networking, and TLS where required.',
    check: (context) => {
      const values = context.environment.values
      const urls = [...values.keys()].filter((key) => /(?:^|_)REDIS_URL$/.test(key))
      const required = values.get('CACHE_STRATEGY')?.toLowerCase() === 'redis' || /\bredis\b/i.test(context.collectDeploymentText())
      if (!urls.length && !required) return { status: 'skipped', summary: 'No Redis configuration was detected.' }
      if (!urls.length) return problems(['REDIS_URL'], 'Redis is referenced without production connection credentials.')
      return problems(urls.filter((key) => !credentialUrl(values.get(key), ['redis:', 'rediss:'])), 'Redis connections lack a strong password or have invalid configuration.')
    },
  }),
  define({
    id: 'services-other-credentials', title: 'Supporting services avoid default credentials', category: 'Services', severity: 'high',
    remediation: 'Set strong unique search, queue, SMTP, and object-storage credentials for enabled services. Prefer workload identities for AWS and verify service-side authentication separately.',
    check: ({ environment }) => {
      const values = environment.values
      const issues: string[] = []
      for (const [key, value] of values) {
        if (/^(?:MEILI|MEILISEARCH|OPENSEARCH|ELASTICSEARCH|RABBITMQ|MINIO|SMTP|S3|AWS)_[A-Z0-9_]*(?:PASSWORD|SECRET_ACCESS_KEY|MASTER_KEY|API_KEY)$/.test(key)
          && value && weakSecret(value, 16)) issues.push(key)
      }
      if (values.get('MEILISEARCH_HOST') || values.get('MEILISEARCH_URL') || values.get('MEILI_HOST')) {
        if (weakSecret(values.get('MEILISEARCH_API_KEY') || values.get('MEILISEARCH_MASTER_KEY') || values.get('MEILI_MASTER_KEY'), 16)) issues.push('MEILISEARCH_API_KEY')
      }
      for (const prefix of ['OPENSEARCH', 'ELASTICSEARCH', 'RABBITMQ']) {
        const key = `${prefix}_URL`
        if (values.get(key) && !credentialUrl(values.get(key), prefix === 'RABBITMQ' ? ['amqp:', 'amqps:'] : ['https:', 'http:'], values.get(`${prefix}_PASSWORD`))
          && weakSecret(values.get(`${prefix}_API_KEY`), 16)) issues.push(key)
      }
      if (values.get('SMTP_USER') && weakSecret(values.get('SMTP_PASSWORD'), 16)) issues.push('SMTP_PASSWORD')
      if (values.get('AWS_ACCESS_KEY_ID') && weakSecret(values.get('AWS_SECRET_ACCESS_KEY'), 32)) issues.push('AWS_SECRET_ACCESS_KEY')
      if (values.get('S3_ACCESS_KEY_ID') && weakSecret(values.get('S3_SECRET_ACCESS_KEY'), 32)) issues.push('S3_SECRET_ACCESS_KEY')
      if (values.get('OM_INTEGRATION_STORAGE_S3_ACCESS_KEY_ID') && weakSecret(values.get('OM_INTEGRATION_STORAGE_S3_SECRET_ACCESS_KEY'), 32)) issues.push('OM_INTEGRATION_STORAGE_S3_SECRET_ACCESS_KEY')
      if (values.get('VAULT_ADDR') && weakSecret(values.get('VAULT_TOKEN'), 16)) issues.push('VAULT_TOKEN')
      const presetKeys = ['OM_INTEGRATION_STORAGE_S3_ACCESS_KEY_ID', 'OM_INTEGRATION_STORAGE_S3_SECRET_ACCESS_KEY', 'OM_INTEGRATION_STORAGE_S3_REGION', 'OM_INTEGRATION_STORAGE_S3_BUCKET']
      if (presetKeys.some((key) => values.get(key))) issues.push(...presetKeys.filter((key) => !values.get(key)))
      if (booleanSetting(values.get('OM_ENABLE_STORAGE_S3')) === true && !values.get('AWS_ROLE_ARN') && !values.get('AWS_WEB_IDENTITY_TOKEN_FILE')
        && !(values.get('AWS_ACCESS_KEY_ID') && !weakSecret(values.get('AWS_SECRET_ACCESS_KEY'), 32))
        && !(values.get('S3_ACCESS_KEY_ID') && !weakSecret(values.get('S3_SECRET_ACCESS_KEY'), 32))
        && !(presetKeys.every((key) => values.get(key)) && !weakSecret(values.get('OM_INTEGRATION_STORAGE_S3_SECRET_ACCESS_KEY'), 32))) {
        return issues.length ? problems(issues, 'Supporting service credentials are weak or incomplete.') : { status: 'warning', summary: 'S3 is enabled without explicit credentials or a role setting; verify the platform workload identity.' }
      }
      return problems(issues, 'Supporting service credentials are weak or incomplete.')
    },
  }),
  define({
    id: 'runtime-production-environment', title: 'Effective environment targets production', category: 'Runtime', severity: 'high',
    remediation: 'Run in the deployed process environment. Set NODE_ENV=production, a canonical HTTPS APP_URL, explicit origin allowlists, and the exact trusted proxy depth. Resolve environment substitutions.',
    check: ({ environment }) => {
      const values = environment.values
      const issues: string[] = []
      if (values.get('NODE_ENV') !== 'production') issues.push('NODE_ENV')
      try {
        const url = new URL(values.get('APP_URL') ?? '')
        if (url.protocol !== 'https:' || url.username || url.password || /^(?:localhost|127\.|0\.0\.0\.0|\[::1\])/.test(url.hostname)) issues.push('APP_URL')
      } catch { issues.push('APP_URL') }
      for (const key of ['APP_ALLOWED_ORIGINS', 'CHECKOUT_ALLOWED_ORIGINS', 'DOCUMENTS_COLLAB_ALLOWED_ORIGINS']) {
        const raw = values.get(key)
        if (key !== 'APP_ALLOWED_ORIGINS' && !raw) continue
        const origins = (raw ?? '').split(',').map((value) => value.trim())
        if (origins.some((origin) => {
          try { const url = new URL(origin); return url.protocol !== 'https:' || origin.includes('*') || Boolean(url.username || url.password) }
          catch { return true }
        })) issues.push(key)
      }
      if (!/^\d+$/.test(values.get('RATE_LIMIT_TRUST_PROXY_DEPTH') ?? '')) issues.push('RATE_LIMIT_TRUST_PROXY_DEPTH')
      for (const [key, value] of values) if (/\$\{[^}]+\}/.test(value) && /^[A-Z][A-Z0-9_]*$/.test(key)) issues.push(key)
      if (environment.unreadableFiles.length) return { status: 'fail', summary: 'Production environment files could not be safely read or parsed.', evidence: environment.unreadableFiles.map((file) => `Unreadable configuration: ${file}`) }
      return problems(issues, 'The effective environment has missing, invalid, or development settings.')
    },
  }),
  define({
    id: 'runtime-tracing-disabled', title: 'Tracing and debug switches are disabled', category: 'Runtime', severity: 'high',
    remediation: 'Disable debug, SQL logging, profiling, autologin, test injection, and tracing flags. Use TELEMETRY_BACKEND=noop and OTEL_TRACES_EXPORTER=none (or OTEL_SDK_DISABLED=true).',
    check: ({ environment }) => {
      const issues: string[] = []
      for (const [key, value] of environment.values) {
        if (/(?:DEBUG|TRACE|TRACING|PROFILE|DEVTOOLS|AUTOLOGIN|TEST_INJECT|DEMO_MODE|EMERGENCY_BYPASS)/.test(key)
          && !/^(?:OTEL_TRACES_EXPORTER|TELEMETRY_TRUST_INBOUND_TRACE)$/.test(key)
          && (booleanSetting(value) === true || (/AUTOLOGIN/.test(key) && Boolean(value.trim()) && booleanSetting(value) !== false))) issues.push(key)
      }
      const debug = environment.values.get('DEBUG')
      if (debug?.trim() && booleanSetting(debug) !== false) issues.push('DEBUG')
      if (/--(?:inspect|prof|trace)(?:[-=\s]|$)/.test(environment.values.get('NODE_OPTIONS') ?? '')) issues.push('NODE_OPTIONS')
      const backend = environment.values.get('TELEMETRY_BACKEND')?.toLowerCase()
      if (backend && !['noop', 'none', 'off', 'disabled'].includes(backend)) issues.push('TELEMETRY_BACKEND')
      const exporter = environment.values.get('OTEL_TRACES_EXPORTER')?.toLowerCase()
      if (exporter && exporter !== 'none' && booleanSetting(environment.values.get('OTEL_SDK_DISABLED')) !== true) issues.push('OTEL_TRACES_EXPORTER')
      return problems(issues, 'The effective environment enables tracing or development-only diagnostics.')
    },
  }),
  define({
    id: 'permissions-env-files', title: 'Production environment files have private permissions', category: 'Permissions', severity: 'high',
    remediation: 'Use owner-only permissions (0600 or 0400) for environment files and keep them out of Git. On Windows, verify ACLs separately.',
    check: (context) => {
      if (process.platform === 'win32') return { status: 'warning', summary: 'Verify Windows ACLs; POSIX mode checks are unavailable.' }
      const found = PRODUCTION_ENV_FILES.map((file) => ({ file, stat: context.inspectPermissions(file) })).filter(({ stat }) => stat !== null)
      if (!found.length) return { status: 'skipped', summary: 'No local production environment files exist; platform variables have no file modes.' }
      return problems(found.filter(({ stat }) => stat && (stat.symbolicLink || stat.directory || (stat.mode & 0o077) !== 0 || (stat.mode & 0o400) === 0)).map(({ file }) => file), 'Environment files are accessible beyond their owner or cannot be safely inspected.')
    },
  }),
  define({
    id: 'permissions-upload-directories', title: 'Private upload storage has restricted permissions', category: 'Permissions', severity: 'high',
    remediation: 'Give the app owner read/write/traverse access to private storage, remove world access, and keep uploaded files non-executable. Use 0700/0750 directories and 0600/0640 files; verify volume ownership and remote storage separately.',
    check: (context) => {
      if (process.platform === 'win32') return { status: 'warning', summary: 'Verify Windows ACLs for private uploads; POSIX mode checks are unavailable.' }
      const locations = new Map(['uploads', 'storage', 'public/uploads', 'var/uploads'].map((file) => [file, file]))
      for (const key of ['UPLOADS_DIR', 'STORAGE_PATH', 'ATTACHMENTS_STORAGE_PATH', 'ATTACHMENTS_STORAGE_ROOT', ...[...context.environment.values.keys()].filter((key) => /^ATTACHMENTS_PARTITION_[A-Z0-9_]+_ROOT$/.test(key))]) {
        const location = context.environment.values.get(key)
        if (location) locations.set(key, location)
      }
      const inspected = [...locations].map(([label, location]) => ({ label, stat: context.inspectStoragePermissions(location) })).filter(({ stat }) => stat !== null)
      const unsafe = inspected.filter(({ stat }) => stat && stat.unsafe > 0)
      if (unsafe.length) return problems(unsafe.map(({ label }) => label), 'Private uploads have excessive permissions, executable files, or missing owner access.')
      if (!inspected.length || inspected.some(({ stat }) => stat?.incomplete)) return { status: 'warning', summary: 'Upload storage is absent, inaccessible, linked, or exceeds the metadata traversal limit; verify deployed permissions.' }
      return { status: 'pass', summary: 'Inspected private storage has restricted POSIX modes; file contents were not opened.' }
    },
  }),
]
