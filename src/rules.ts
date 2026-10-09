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

function templateKeys(context: ScanContext): Map<string, string> {
  const source = context.readText('.env.example') ?? ''
  const entries = new Map<string, string>()
  for (const line of source.split(/\r?\n/)) {
    const match = line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/)
    if (match?.[1] !== undefined && match[2] !== undefined) entries.set(match[1], match[2].trim())
  }
  return entries
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
    id: 'secrets-ignore-policy', title: 'Sensitive local files are ignored', category: 'Secrets', severity: 'high',
    remediation: 'Ignore live .env files, private keys, local MCP credentials, npm credentials, and raw agent session exports.',
    check: (context) => {
      const source = context.readText('.gitignore')
      if (!source) return { status: 'fail', summary: 'No readable .gitignore defines a sensitive-file policy.' }
      const required = ['.env', '*.pem', '.mcp.json', '.npmrc', '.ai/session-exports/']
      const missing = required.filter((pattern) => !source.includes(pattern))
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
      const keys = templateKeys(context)
      const missing = ['NODE_ENV', 'APP_URL', 'DATABASE_URL'].filter((key) => !keys.has(key))
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
    check: (context) => templateKeys(context).has('RATE_LIMIT_TRUST_PROXY_DEPTH')
      ? { status: 'warning', summary: 'RATE_LIMIT_TRUST_PROXY_DEPTH is documented; verify its live value matches the deployed proxy chain.' }
      : { status: 'fail', summary: 'RATE_LIMIT_TRUST_PROXY_DEPTH is absent from the configuration template.' },
  }),
  rule({
    id: 'edge-allowed-origins', title: 'Browser and real-time origins are restricted', category: 'Edge', severity: 'high',
    remediation: 'Configure APP_ALLOWED_ORIGINS and capability-specific origin lists with only intended HTTPS origins.',
    check: (context) => {
      const keys = templateKeys(context)
      const required = ['APP_ALLOWED_ORIGINS']
      const installed = dependencies(context)
      if (installed.has('@open-mercato/checkout')) required.push('CHECKOUT_ALLOWED_ORIGINS')
      if (installed.has('@open-mercato/documents')) required.push('DOCUMENTS_COLLAB_ALLOWED_ORIGINS')
      const missing = required.filter((key) => !keys.has(key))
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
      const required = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options']
      const missing = required.filter((header) => !source.includes(header))
      return missing.length
        ? { status: 'fail', summary: 'The application configuration does not declare the complete security-header baseline.', evidence: missing.map((header) => `Missing header: ${header}`) }
        : { status: 'pass', summary: 'The application declares CSP, HSTS, and MIME-sniffing protection headers.' }
    },
  }),
  rule({
    id: 'operations-health-check', title: 'A deployment health check is wired', category: 'Operations', severity: 'high',
    remediation: 'Expose the standard health route and configure the deployment platform to probe it with bounded timeouts.',
    check: (context) => {
      const route = dependencies(context).has('@open-mercato/core') || context.exists('src/app/api/healthz/route.ts')
      const configured = /\/api\/healthz/.test(context.collectDeploymentText())
      if (route && configured) return { status: 'pass', summary: 'The health route exists and deployment configuration references it.' }
      const evidence = [!route ? 'Missing src/app/api/healthz/route.ts.' : '', !configured ? 'Deployment configuration does not reference /api/healthz.' : ''].filter(Boolean)
      return { status: 'fail', summary: 'Health-check wiring is incomplete.', evidence }
    },
  }),
  rule({
    id: 'container-non-root-user', title: 'Production containers run as non-root', category: 'Containers', severity: 'high',
    remediation: 'Create an unprivileged runtime user and switch to it with USER in the final production image.',
    check: (context) => {
      const source = context.readText('Dockerfile')
      if (!source) return { status: 'skipped', summary: 'No Dockerfile is present.' }
      const users = [...source.matchAll(/^USER\s+([^\s#]+)/gmi)].map((match) => match[1]?.toLowerCase()).filter(Boolean)
      return users.length > 0 && users.at(-1) !== 'root' && users.at(-1) !== '0'
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
    id: 'release-database-migrations', title: 'Database migrations are part of release startup', category: 'Release', severity: 'high',
    remediation: 'Run the supported database migration command once per release before accepting traffic.',
    check: (context) => /(?:db[: ]migrate|mercato\s+db\s+migrate)/i.test(context.collectDeploymentText())
      ? { status: 'pass', summary: 'Deployment configuration includes a database migration step.' }
      : { status: 'fail', summary: 'No database migration step was found in deployment configuration.' },
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
      const keys = templateKeys(context)
      const config = ['docker/otel-collector-config.yaml', 'docker/otel-collector-config.yml'].filter(context.exists)
      const hasSetting = [...keys.keys()].some((key) => /^(?:OTEL_|NEW_RELIC_|SENTRY_)/.test(key))
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
      return typeof node === 'string' && /(?:>=|\^|~)?\s*2[4-9]/.test(node)
        ? { status: 'pass', summary: 'package.json requires Node.js 24 or newer.', evidence: ['A supported Node.js engine constraint is declared.'] }
        : { status: 'fail', summary: 'package.json does not require a supported Node.js runtime.' }
    },
  }),
  rule({
    id: 'runtime-debug-features-disabled', title: 'Development-only features default off', category: 'Runtime', severity: 'high',
    remediation: 'Keep debug, profiling, autologin, test injection, and DevTools switches disabled in the production template.',
    check: (context) => {
      const risky = [...templateKeys(context)].filter(([key, value]) => /(?:DEBUG|PROFILE|DEVTOOLS|AUTOLOGIN|TEST_INJECT)/.test(key) && /^(?:1|true|yes|on)$/i.test(value)).map(([key]) => key)
      return risky.length === 0
        ? { status: 'pass', summary: 'No development-only switch defaults to enabled in .env.example.' }
        : { status: 'fail', summary: 'Development-only switches default to enabled.', evidence: risky.map((key) => `Enabled template switch: ${key}`) }
    },
  }),
] as const
