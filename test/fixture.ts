import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

const FILES: Record<string, string> = {
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
    'const securityHeaders = [',
    '  { key: "Content-Security-Policy", value: "default-src self; frame-ancestors self" },',
    '  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },',
    '  { key: "X-Content-Type-Options", value: "nosniff" },',
    '  { key: "X-Frame-Options", value: "SAMEORIGIN" },',
    ']',
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
  '.github/workflows/release.yml': 'on:\n  push:\n    branches: [main]\njobs:\n  validate:\n    steps:\n      - run: yarn generate\n      - run: yarn build\n      - run: yarn test\n      - run: yarn db:migrate --check\n',
  'docs/operations.md': [
    '# Production operations',
    'Use TLS and HTTPS with certificate renewal and the canonical origin.',
    'Use a persistent volume for uploads and storage.',
    'Run database migrate once, then supervise each queue worker.',
    'Back up the database and files and rehearse restore in isolation.',
    'Keep the prior artifact and rehearse rollback or forward-fix procedures.',
  ].join('\n'),
  'yarn.lock': '# fixture lockfile\n',
}

/**
 * `git: 'none'` leaves the fixture outside version control, `'init'` stages everything without a
 * commit (so the worktree is dirty), and `'commit'` produces a clean, revertable worktree.
 * A `files` entry set to `null` omits that default file.
 */
export type FixtureOptions = {
  files?: Record<string, string | null>
  git?: 'none' | 'init' | 'commit'
}

function git(root: string, args: string[]): void {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed for test fixture: ${result.stderr}`)
}

function insideWorktree(directory: string): boolean {
  const result = spawnSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: directory, encoding: 'utf8' })
  return result.status === 0 && result.stdout.trim() === 'true'
}

/**
 * Picks a base directory that is genuinely outside any git worktree, so the non-git fixture is
 * really ungoverned. `TMPDIR` can point inside a checkout, which would silently make the
 * "not a git working tree" case untestable.
 */
function nonRepositoryBase(): string {
  for (const candidate of [os.tmpdir(), '/tmp', path.join(os.homedir(), '.cache'), os.homedir()]) {
    if (!candidate || !fs.existsSync(candidate)) continue
    let probe: string
    try {
      probe = fs.mkdtempSync(path.join(candidate, 'mercato-readiness-probe-'))
    } catch {
      continue
    }
    let usable = !insideWorktree(probe)
    try {
      // A candidate can exist, be ungoverned, and still be out of quota.
      fs.writeFileSync(path.join(probe, 'probe'), 'probe')
    } catch {
      usable = false
    }
    fs.rmSync(probe, { recursive: true, force: true })
    if (usable) return candidate
  }
  throw new Error('no writable directory outside a git worktree is available for the non-git fixture')
}

/** The default fixture tree, exported so tests can derive deliberately broken variants. */
export const DEFAULT_FIXTURE_FILES: Readonly<Record<string, string>> = FILES

export function makeAppFixture(options: FixtureOptions = {}): string {
  const base = options.git === 'none' ? nonRepositoryBase() : os.tmpdir()
  const root = fs.mkdtempSync(path.join(base, 'mercato-readiness-'))
  for (const [relativePath, contents] of Object.entries({ ...FILES, ...options.files })) {
    if (contents === null) continue
    const destination = path.join(root, relativePath)
    fs.mkdirSync(path.dirname(destination), { recursive: true })
    fs.writeFileSync(destination, contents)
  }
  const mode = options.git ?? 'init'
  if (mode === 'none') return root
  git(root, ['init', '--quiet'])
  git(root, ['add', '.'])
  if (mode === 'commit') {
    git(root, ['-c', 'user.name=Readiness Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '--no-gpg-sign', '-m', 'fixture baseline'])
  }
  return root
}

/** Porcelain status of a fixture, used to prove an apply changed nothing on a second run. */
export function fixtureStatus(root: string): string {
  return spawnSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).stdout
}

/** Commits whatever an apply just wrote, which is the real workflow before a second apply. */
export function commitFixture(root: string, message: string): void {
  git(root, ['add', '-A'])
  git(root, ['-c', 'user.name=Readiness Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '--no-gpg-sign', '-m', message])
}

/** A scratch directory for saved reports, deliberately outside the scanned application. */
export function makeReportDirectory(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'mercato-readiness-report-'))
}

const CEZAR_RUN_STUB = `#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
fs.writeFileSync(path.join(here, 'invocation.json'), JSON.stringify({ argv: process.argv.slice(2) }, null, 2))
process.stdout.write('stub cezar-run invoked\\n')
`

export type CezarRunStub = {
  /** Path to pass as --cezar-run; never a real agent. */
  binary: string
  /** Reads what the stub was invoked with, or null when it was never spawned. */
  invocation: () => { argv: string[] } | null
  remove: () => void
}

export function makeCezarRunStub(): CezarRunStub {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mercato-readiness-cezar-'))
  const binary = path.join(directory, 'cezar-run.mjs')
  const log = path.join(directory, 'invocation.json')
  fs.writeFileSync(binary, CEZAR_RUN_STUB, { mode: 0o755 })
  return {
    binary,
    invocation: () => fs.existsSync(log) ? JSON.parse(fs.readFileSync(log, 'utf8')) as { argv: string[] } : null,
    remove: () => fs.rmSync(directory, { recursive: true, force: true }),
  }
}

export function removeFixture(root: string): void {
  fs.rmSync(root, { recursive: true, force: true })
}
