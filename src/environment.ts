import { parseEnv } from 'node:util'
import { PRODUCTION_ENV_FILES, readProductionEnvText } from './files.js'

export type Environment = {
  values: ReadonlyMap<string, string>
  sources: readonly string[]
  unreadableFiles: readonly string[]
}

const RELEVANT = /^(?:NODE_ENV|NODE_OPTIONS|APP_URL|INTERNAL_APP_ORIGIN|PLATFORM_PRIMARY_HOST|DATABASE_URL|PG[A-Z0-9_]+|POSTGRES_[A-Z0-9_]+|JWT_[A-Z0-9_]+|[A-Z0-9_]+_JWT_SECRET(?:_[A-Z0-9_]+)?|AUTH_SECRET|NEXTAUTH_SECRET|TENANT_DATA_ENCRYPTION(?:_[A-Z0-9_]+)?|ALLOW_DERIVED_KMS_FALLBACK|VAULT_[A-Z0-9_]+|(?:CACHE_|EVENTS_|QUEUE_|DOCUMENTS_COLLAB_)?REDIS_[A-Z0-9_]+|(?:MEILI|MEILISEARCH|OPENSEARCH|ELASTICSEARCH|RABBITMQ|S3|AWS|MINIO|SMTP)_[A-Z0-9_]+|TELEMETRY_[A-Z0-9_]+|OTEL_[A-Z0-9_]+|NEXT_PUBLIC_[A-Z0-9_]+|[A-Z0-9_]*(?:DEBUG|TRACE|TRACING|PROFILE|DEVTOOLS|AUTOLOGIN|TEST_INJECT|DEMO_MODE|EMERGENCY_BYPASS)[A-Z0-9_]*|APP_ALLOWED_ORIGINS|CHECKOUT_ALLOWED_ORIGINS|DOCUMENTS_COLLAB_ALLOWED_ORIGINS|RATE_LIMIT_TRUST_PROXY_DEPTH|CACHE_STRATEGY|UPLOADS_DIR|STORAGE_PATH|ATTACHMENTS_STORAGE_PATH|ATTACHMENTS_STORAGE_ROOT|ATTACHMENTS_PARTITION_[A-Z0-9_]+_ROOT|OM_INTEGRATION_STORAGE_S3_[A-Z0-9_]+|OM_ENABLE_STORAGE_S3)$/

export function loadEnvironment(root: string, exists: (file: string) => boolean, inherited: Readonly<Record<string, string | undefined>> = process.env): Environment {
  const values = new Map<string, string>()
  const sources: string[] = []
  const unreadableFiles: string[] = []
  // Next.js production precedence, from lowest to highest. Templates never supply live values.
  for (const file of PRODUCTION_ENV_FILES) {
    const text = readProductionEnvText(root, file)
    if (text === null) {
      if (exists(file)) unreadableFiles.push(file)
      continue
    }
    try {
      for (const [key, value] of Object.entries(parseEnv(text))) {
        if (typeof value === 'string' && /^[A-Z][A-Z0-9_]*$/.test(key)) values.set(key, value)
      }
      sources.push(file)
    } catch {
      unreadableFiles.push(file)
    }
  }
  const inheritedNames = new Set<string>()
  const referenced = new Set([...values.values()].flatMap((value) => [...value.matchAll(/\$\{?([A-Z][A-Z0-9_]*)/g)].map((match) => match[1])))
  let hasInherited = false
  for (const [key, value] of Object.entries(inherited)) {
    if (value !== undefined && (RELEVANT.test(key) || values.has(key) || referenced.has(key))) {
      values.set(key, value)
      inheritedNames.add(key)
      hasInherited = true
    }
  }
  if (hasInherited) sources.push('process environment')
  const expand = (value: string, seen: ReadonlySet<string>): string => value.replace(/(?<!\\)\$\{([A-Z][A-Z0-9_]*)(?::-(.*?))?\}|(?<!\\)\$([A-Z][A-Z0-9_]*)/g,
    (original: string, bracketed: string | undefined, fallback: string | undefined, plain: string | undefined) => {
      const key = bracketed ?? plain ?? ''
      if (seen.has(key) || seen.size > 32) return original
      const resolved = values.get(key)
      if (resolved === undefined || (resolved === '' && fallback !== undefined)) return fallback ?? original
      return inheritedNames.has(key) ? resolved : expand(resolved, new Set([...seen, key]))
    })
  // Shell commands are always literal. No shell, eval, dotenv plugin, or target code is loaded.
  for (const [key, value] of values) {
    if (!inheritedNames.has(key)) values.set(key, expand(value, new Set([key])).replaceAll('\\$', '$'))
  }
  return { values, sources, unreadableFiles }
}

export function booleanSetting(value: string | undefined): boolean | undefined {
  if (/^(?:true|1|yes|on)$/i.test(value?.trim() ?? '')) return true
  if (/^(?:false|0|no|off)$/i.test(value?.trim() ?? '')) return false
  return undefined
}

export function weakSecret(value: string | undefined, minimum = 32): boolean {
  const trimmed = value?.trim() ?? ''
  return trimmed.length < minimum
    || /(?:change[-_ ]?me|replace[-_ ]?me|your[-_ ]|example|placeholder|dev[-_ ]?(?:secret|key)|om-dev-tenant-encryption|meilisearch-dev-key|^postgres$|^redis$|^password$|^secret$|\$\{|^<.*>$)/i.test(trimmed)
    || new Set(trimmed).size < 8
}
