import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

// Synthetic test values, never actual service credentials.
export const PRODUCTION_ENV: Readonly<Record<string, string>> = {
  NODE_ENV: 'production',
  APP_URL: 'https://shop.test.invalid',
  APP_ALLOWED_ORIGINS: 'https://shop.test.invalid',
  RATE_LIMIT_TRUST_PROXY_DEPTH: '1',
  JWT_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  TENANT_DATA_ENCRYPTION: 'yes',
  TENANT_DATA_ENCRYPTION_FALLBACK_KEY: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
  DATABASE_URL: 'postgresql://app:0123456789abcdef0123456789abcdef@db.test.invalid/app',
  REDIS_URL: 'rediss://app:abcdef0123456789abcdef0123456789@cache.test.invalid:6379',
  TELEMETRY_BACKEND: 'noop',
  OTEL_TRACES_EXPORTER: 'none',
}

export const FILES: Readonly<Record<string, string>> = {
  'package.json': JSON.stringify({
    name: 'readiness-fixture',
    private: true,
    engines: { node: '>=24.0.0' },
    scripts: {
      build: 'cross-env NODE_ENV=production next build',
      start: 'mercato server start',
    },
    dependencies: {
      '@open-mercato/core': '1.0.0',
      '@open-mercato/queue': '1.0.0',
      '@open-mercato/checkout': '1.0.0',
      '@open-mercato/documents': '1.0.0',
    },
  }, null, 2),
  'src/modules.ts': 'export default []\n',
  '.env.example': [
    'NODE_ENV=production',
    'APP_URL=https://shop.example.com',
    'DATABASE_URL=',
    'INTERNAL_APP_ORIGIN=',
    'PLATFORM_PRIMARY_HOST=',
    'RATE_LIMIT_TRUST_PROXY_DEPTH=1',
    'APP_ALLOWED_ORIGINS=https://shop.example.com',
    'CHECKOUT_ALLOWED_ORIGINS=https://shop.example.com',
    'DOCUMENTS_COLLAB_ALLOWED_ORIGINS=https://shop.example.com',
    'OTEL_EXPORTER_OTLP_ENDPOINT=',
    'CACHE_STRATEGY=redis',
    'REDIS_URL=',
    'NEXT_PUBLIC_UMES_DEVTOOLS=false',
    'NEXT_PUBLIC_OM_EXAMPLE_CHECKOUT_TEST_INJECTIONS_ENABLED=false',
  ].join('\n'),
  '.gitignore': [
    '.env',
    '.env.production',
    '.env.local',
    '.env.*.local',
    '!.env.example',
    '*.pem',
    '*.key',
    '.mcp.json',
    '.npmrc',
    '.ai/session-exports/',
  ].join('\n'),
  'next.config.ts': [
    "const securityHeaders = ['Content-Security-Policy', 'Referrer-Policy', 'X-Content-Type-Options', 'X-Frame-Options']",
    'export default { async headers() { return [{ source: "/:path*", headers: securityHeaders }] } }',
  ].join('\n'),
  Dockerfile: [
    'FROM node:24-alpine',
    'RUN yarn install --immutable',
    'RUN adduser -D mercato',
    'USER mercato',
  ].join('\n'),
  'railway.toml': '[deploy]\nhealthcheckPath = "/api/healthz"\nstartCommand = "yarn db:migrate && yarn start"\n',
  'railway.worker.toml': '[deploy]\nstartCommand = "yarn mercato worker"\n',
  'docker-compose.fullapp.yml': 'services:\n  app:\n    volumes:\n      - uploads:/app/storage\nvolumes:\n  uploads:\n',
  'docker/otel-collector-config.yaml': 'receivers:\n  otlp:\nexporters:\n  debug:\n',
  '.github/workflows/release.yml': 'jobs:\n  validate:\n    steps:\n      - run: yarn generate\n      - run: yarn build\n      - run: yarn test\n      - run: yarn db:migrate --check\n',
  'docs/operations.md': [
    '# Production operations',
    'Use TLS and HTTPS with certificate renewal and the canonical origin.',
    'Use a persistent volume for uploads and storage.',
    'Run database migrate once, then supervise each queue worker.',
    'Create database and file backups and rehearse restore in isolation.',
    'Keep the prior artifact and rehearse rollback or forward-fix procedures.',
  ].join('\n'),
  'yarn.lock': '# fixture lockfile\n',
}

export function makeAppFixture(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mercato-readiness-'))
  for (const [relativePath, contents] of Object.entries(FILES)) {
    const destination = path.join(root, relativePath)
    fs.mkdirSync(path.dirname(destination), { recursive: true })
    fs.writeFileSync(destination, contents)
  }
  const init = spawnSync('git', ['init', '--quiet'], { cwd: root })
  if (init.status !== 0) throw new Error('git init failed for test fixture')
  const add = spawnSync('git', ['add', '.'], { cwd: root })
  if (add.status !== 0) throw new Error('git add failed for test fixture')
  return root
}

export function removeFixture(root: string): void {
  fs.rmSync(root, { recursive: true, force: true })
}
