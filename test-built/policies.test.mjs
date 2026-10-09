import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const cli = path.join(repositoryRoot, 'dist', 'cli.js')

function fixture(files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mercato-readiness-policy-'))
  const defaults = {
    'package.json': JSON.stringify({
      name: 'policy-fixture', private: true, engines: { node: '>=24' },
      scripts: { build: 'cross-env NODE_ENV=production next build', start: 'mercato server start' },
      dependencies: { '@open-mercato/core': '1.0.0', '@open-mercato/queue': '1.0.0' },
    }),
    'src/modules.ts': 'export default []\n',
    '.env.example': 'NODE_ENV=production\nAPP_URL=https://example.com\nDATABASE_URL=\nINTERNAL_APP_ORIGIN=\nPLATFORM_PRIMARY_HOST=\nRATE_LIMIT_TRUST_PROXY_DEPTH=1\nAPP_ALLOWED_ORIGINS=https://example.com\nCACHE_STRATEGY=redis\nREDIS_URL=\n',
    '.gitignore': '.env\n.env*\n.env.production\n.env.local\n.env.*.local\n!.env.example\n*.pem\n*.key\n.mcp.json\n.npmrc\n.ai/session-exports/\n',
    'yarn.lock': '# lock\n',
    Dockerfile: 'FROM node:24\nRUN yarn install --immutable\nUSER app\n',
    'next.config.ts': 'const securityHeaders = [\n  { key: "Content-Security-Policy", value: "default-src self; frame-ancestors self" },\n  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },\n  { key: "X-Content-Type-Options", value: "nosniff" },\n  { key: "X-Frame-Options", value: "SAMEORIGIN" },\n]\nexport default { async headers() { return [{ source: "/:path*", headers: securityHeaders }] } }\n',
    'railway.toml': '[deploy]\nhealthcheckPath = "/api/healthz"\nstartCommand = "yarn db:migrate && yarn start"\n',
    'railway.worker.toml': '[deploy]\nstartCommand = "yarn mercato worker"\n',
    'docker-compose.fullapp.yml': 'services:\n  app:\n    volumes: ["uploads:/app/storage"]\n',
    '.github/workflows/release.yml': 'on:\n  push:\n    branches: [main]\njobs:\n  validate:\n    steps:\n      - run: yarn generate\n      - run: yarn build\n      - run: yarn test\n      - run: yarn db:migrate --check\n',
    'docs/operations.md': 'TLS HTTPS certificate volume storage backup restore rollback worker\n',
  }
  for (const [relativePath, contents] of Object.entries({ ...defaults, ...files })) {
    const destination = path.join(root, relativePath)
    fs.mkdirSync(path.dirname(destination), { recursive: true })
    fs.writeFileSync(destination, contents)
  }
  assert.equal(spawnSync('git', ['init', '--quiet'], { cwd: root }).status, 0)
  assert.equal(spawnSync('git', ['add', '.'], { cwd: root }).status, 0)
  return root
}

function scan(root) {
  const result = spawnSync(process.execPath, [cli, root, '--format', 'json'], { cwd: repositoryRoot, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  const report = JSON.parse(result.stdout)
  return new Map(report.results.map((entry) => [entry.id, entry]))
}

function overwrite(root, relativePath, contents) {
  const destination = path.join(root, relativePath)
  fs.mkdirSync(path.dirname(destination), { recursive: true })
  fs.writeFileSync(destination, contents)
}

test('built CLI detects expanded live-env and credential path families without reading values', () => {
  const secret = 'PRIVATE_SENTINEL_4f13b8'
  const root = fixture({ '.env-prod': secret, '.envrc': secret, id_ecdsa: secret, '.aws/credentials': secret })
  try {
    assert.equal(spawnSync('git', ['add', '--force', '.env-prod', '.envrc', 'id_ecdsa', '.aws/credentials'], { cwd: root }).status, 0)
    const result = spawnSync(process.execPath, [cli, root, '--format', 'json'], { cwd: repositoryRoot, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    const report = JSON.parse(result.stdout)
    const findings = new Map(report.results.map((entry) => [entry.id, entry]))
    assert.equal(findings.get('secrets-live-env-untracked')?.status, 'fail')
    assert.equal(findings.get('secrets-no-tracked-credentials')?.status, 'fail')
    assert.equal(result.stdout.includes(secret), false)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('built CLI evaluates effective policies and rejects non-proof text', () => {
  const root = fixture({
    'package.json': JSON.stringify({
      name: 'policy-fixture', private: true, engines: { node: '>=24' },
      scripts: { build: 'echo NODE_ENV=production && next build', start: 'mercato server start' },
      dependencies: { '@open-mercato/core': '1.0.0', '@open-mercato/queue': '1.0.0' },
    }),
    '.env.example': 'NODE_ENV=production\nAPP_URL=https://example.com\nDATABASE_URL=\nINTERNAL_APP_ORIGIN=\nPLATFORM_PRIMARY_HOST=\nRATE_LIMIT_TRUST_PROXY_DEPTH=1\nAPP_ALLOWED_ORIGINS=https://example.com\nQUERY_ENGINE_DEBUG_SQL=enabled\nCACHE_STRATEGY=redis\nREDIS_URL=\n',
    Dockerfile: 'FROM node:24 AS secure\nRUN echo preparing # npm ci\nRUN npm install\nUSER 1001:1001\nFROM secure AS runtime\n',
    'next.config.ts': 'const active = true // Content-Security-Policy Referrer-Policy X-Content-Type-Options X-Frame-Options\nexport default { active }\n',
    'railway.worker.toml': '',
    'docker-compose.fullapp.yml': 'x-db: &db\n  image: postgres:17\n  ports: ["5432:5432"]\nservices:\n  database:\n    <<: *db\n',
    '.github/workflows/release.yml': 'jobs:\n  validate:\n    steps:\n      - run: yarn generate\n      - run: yarn build\n      - run: yarn test || true\n      - run: yarn db:migrate --check\n        continue-on-error: ${{ matrix.nonblocking }}\n',
  })
  try {
    const findings = scan(root)
    assert.equal(findings.get('infrastructure-private-services')?.status, 'fail')
    assert.equal(findings.get('container-non-root-user')?.status, 'pass')
    assert.equal(findings.get('release-validation-gate')?.status, 'fail')
    assert.equal(findings.get('runtime-debug-features-disabled')?.status, 'fail')
    assert.equal(findings.get('operations-worker-topology')?.status, 'fail')
    assert.equal(findings.get('workers-release-parity')?.status, 'skipped')
    assert.equal(findings.get('runtime-production-scripts')?.status, 'fail')
    assert.equal(findings.get('edge-security-headers')?.status, 'fail')
    assert.equal(findings.get('supply-chain-immutable-install')?.status, 'fail')

    overwrite(root, 'docker-compose.fullapp.yml', 'services:\n  redis:\n    image: redis:7\n    network_mode: host\n')
    assert.equal(scan(root).get('infrastructure-private-services')?.status, 'fail')

    const workflowPrefix = 'on:\n  push:\njobs:\n  validate:\n    steps:\n      - run: yarn generate\n      - run: yarn build\n'
    overwrite(root, '.github/workflows/release.yml', `${workflowPrefix}      - run: yarn test || true\n      - run: yarn db:migrate --check\n`)
    assert.equal(scan(root).get('release-validation-gate')?.status, 'fail')
    overwrite(root, '.github/workflows/release.yml', `${workflowPrefix}      - run: yarn test\n      - run: yarn db:migrate --check\n        continue-on-error: \${{ matrix.nonblocking }}\n`)
    assert.equal(scan(root).get('release-validation-gate')?.status, 'fail')

    for (const testCommand of ['yarn test; true', 'yarn test\n          true', 'yarn test | tee test.log']) {
      overwrite(root, '.github/workflows/release.yml', `${workflowPrefix}      - shell: bash {0}\n        run: |\n          ${testCommand}\n      - run: yarn db:migrate --check\n`)
      assert.equal(scan(root).get('release-validation-gate')?.status, 'fail', testCommand)
    }
    for (const shell of [null, 'bash -e {0}']) {
      const testStep = shell ? `      - shell: ${shell}\n        run: yarn test & true\n` : '      - run: yarn test & true\n'
      overwrite(root, '.github/workflows/release.yml', `${workflowPrefix}${testStep}      - run: yarn db:migrate --check\n`)
      assert.equal(scan(root).get('release-validation-gate')?.status, 'fail', shell ?? 'default shell')
    }
    overwrite(root, '.github/workflows/release.yml', 'on:\n  pull_request:\njobs:\n  validate:\n    steps:\n      - run: yarn generate\n      - run: yarn build\n      - run: yarn test\n      - run: yarn db:migrate --check\n')
    assert.equal(scan(root).get('release-validation-gate')?.status, 'fail')
    for (const trigger of ['  workflow_dispatch:', '  workflow_call:', '  push:\n    branches: [feature-only]', '  push:\n    branches: [feature/**]', '  push:\n    tags: [feature-*]', '  release:\n    types: [deleted]', '  push:\n    branches: [main]\n    paths-ignore: ["**"]', '  push:\n    branches-ignore: [main, master, develop]', '  push:\n    branches-ignore: [ma*]']) {
      overwrite(root, '.github/workflows/release.yml', `on:\n${trigger}\njobs:\n  validate:\n    steps:\n      - run: yarn generate\n      - run: yarn build\n      - run: yarn test\n      - run: yarn db:migrate --check\n`)
      assert.equal(scan(root).get('release-validation-gate')?.status, 'fail', trigger)
    }
    overwrite(root, '.github/workflows/release.yml', "on:\n  push:\n    branches: [main]\njobs:\n  validate:\n    steps:\n      - run: |\n          cat <<'COMMANDS'\n          yarn generate\n          yarn build\n          yarn test\n          yarn db:migrate --check\n          COMMANDS\n")
    assert.equal(scan(root).get('release-validation-gate')?.status, 'fail')
    overwrite(root, '.github/workflows/release.yml', 'on:\n  push:\njobs:\n  build:\n    steps:\n      - run: yarn generate\n      - run: yarn build\n')
    overwrite(root, '.github/workflows/other.yml', 'on:\n  push:\njobs:\n  verify:\n    steps:\n      - run: yarn test\n      - run: yarn db:migrate --check\n')
    assert.equal(scan(root).get('release-validation-gate')?.status, 'fail')
    fs.rmSync(path.join(root, '.github/workflows/other.yml'))

    const manifestPath = path.join(root, 'package.json')
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
    manifest.scripts = { build: 'NODE_ENV=production next build || true', start: 'next start' }
    fs.writeFileSync(manifestPath, JSON.stringify(manifest))
    assert.equal(scan(root).get('runtime-production-scripts')?.status, 'fail')
    manifest.scripts = { build: 'NODE_ENV=production next build', start: 'next dev' }
    fs.writeFileSync(manifestPath, JSON.stringify(manifest))
    assert.equal(scan(root).get('runtime-production-scripts')?.status, 'fail')
    for (const scripts of [
      { build: 'NODE_ENV=production next build --help', start: 'next start' },
      { build: 'NODE_ENV=production next build', start: 'next start --help' },
      { build: 'NODE_ENV=production next build --help=true', start: 'next start' },
      { build: 'NODE_ENV=production next build', start: 'next start --version=true' },
      { build: 'NODE_ENV=production next build -h=true', start: 'next start' },
      { build: 'NODE_ENV=production next build', start: 'next start -v=true' },
    ]) {
      manifest.scripts = scripts
      fs.writeFileSync(manifestPath, JSON.stringify(manifest))
      assert.equal(scan(root).get('runtime-production-scripts')?.status, 'fail')
    }

    const baselineIgnore = fs.readFileSync(path.join(root, '.gitignore'), 'utf8')
    overwrite(root, '.gitignore', `${baselineIgnore}\n!.env.production\n!*.pem\n!.env.[p]roduction\n!/.env.staging\n`)
    assert.equal(scan(root).get('secrets-ignore-policy')?.status, 'fail')
    overwrite(root, '.gitignore', baselineIgnore)
    const baselineTemplate = fs.readFileSync(path.join(root, '.env.example'), 'utf8')
    overwrite(root, '.env.example', baselineTemplate.replace('DATABASE_URL=', 'DATABASE_URL=postgres://operator:live-password@database.internal/app'))
    assert.equal(scan(root).get('runtime-env-template')?.status, 'fail')
    overwrite(root, '.env.example', baselineTemplate.replace('DATABASE_URL=', 'DATABASE_URL=postgres://example.com/app?password=live-secret'))
    assert.equal(scan(root).get('runtime-env-template')?.status, 'fail')
    overwrite(root, '.env.example', baselineTemplate.replace('DATABASE_URL=', 'DATABASE_URL="postgres://example.com/app#token=percent%2Dencoded%2Dsecret"'))
    assert.equal(scan(root).get('runtime-env-template')?.status, 'fail')
    for (const value of ['postgres://example.com/app?sslpassword=live-secret', 'postgres://example.com/app?apiKey=live-secret', 'postgres://example.com/app?pwd=live-secret', 'postgres://example.com/app#opaque-live-secret']) {
      overwrite(root, '.env.example', baselineTemplate.replace('DATABASE_URL=', `DATABASE_URL="${value}"`))
      assert.equal(scan(root).get('runtime-env-template')?.status, 'fail', value)
    }
    overwrite(root, '.env.example', baselineTemplate)

    overwrite(root, 'railway.worker.toml', '[deploy]\nstartCommand = "echo worker"\n')
    assert.equal(scan(root).get('operations-worker-topology')?.status, 'fail')
    overwrite(root, 'railway.worker.toml', '[deploy]\nstartCommand = "npm worker"\n')
    assert.equal(scan(root).get('operations-worker-topology')?.status, 'fail')
    for (const command of ['yarn mercato worker || true', 'yarn mercato worker --help']) {
      overwrite(root, 'railway.worker.toml', `[deploy]\nstartCommand = "${command}"\n`)
      assert.equal(scan(root).get('operations-worker-topology')?.status, 'fail', command)
    }
    overwrite(root, 'railway.worker.toml', '[deploy]\nstartCommand = "npm run worker"\n')
    assert.equal(scan(root).get('operations-worker-topology')?.status, 'fail')
    const workerManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
    workerManifest.scripts.worker = 'mercato worker'
    fs.writeFileSync(manifestPath, JSON.stringify(workerManifest))
    assert.equal(scan(root).get('operations-worker-topology')?.status, 'pass')

    overwrite(root, 'railway.toml', '[deploy]\nstartCommand = "echo /api/healthz && echo yarn db:migrate"\n')
    assert.equal(scan(root).get('operations-health-check')?.status, 'fail')
    assert.equal(scan(root).get('release-database-migrations')?.status, 'fail')
    overwrite(root, 'railway.toml', '[build]\nhealthcheckPath = "/api/healthz"\nstartCommand = "yarn db:migrate"\n[deploy]\nstartCommand = "false && yarn db:migrate"\n')
    assert.equal(scan(root).get('operations-health-check')?.status, 'fail')
    assert.equal(scan(root).get('release-database-migrations')?.status, 'fail')
    for (const command of ['exit 0 && yarn db:migrate', 'exec true && yarn db:migrate']) {
      overwrite(root, 'railway.toml', `[deploy]\nstartCommand = "${command}"\n`)
      assert.equal(scan(root).get('release-database-migrations')?.status, 'fail', command)
    }
    for (const healthcheck of ['healthcheck:\n      disable: true\n      test: ["CMD", "curl", "http://localhost:3000/api/healthz"]', 'healthcheck:\n      test: ["CMD-SHELL", "echo curl http://localhost:3000/api/healthz"]', 'healthcheck:\n      test: ["CMD-SHELL", "curl http://localhost:3000/api/healthz || true"]']) {
      overwrite(root, 'docker-compose.fullapp.yml', `services:\n  app:\n    ${healthcheck}\n`)
      assert.equal(scan(root).get('operations-health-check')?.status, 'fail', healthcheck)
    }

    overwrite(root, 'railway.worker.toml', '[deploy]\nstartCommand = "yarn mercato worker"\n')
    overwrite(root, 'docker-compose.fullapp.yml', 'services:\n  app:\n    image: app:abcdef1\n  worker:\n    image: worker:fedcba9\n    command: yarn mercato worker\n')
    assert.equal(scan(root).get('workers-release-parity')?.status, 'fail')

    overwrite(root, 'next.config.ts', 'const unused = "Content-Security-Policy Referrer-Policy X-Content-Type-Options X-Frame-Options"\nexport default {}\n')
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', 'const unused = ["Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"]\nexport default { async headers() { return [] } }\n')
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', 'const securityHeaders = ["Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"]\nexport default { async headers() { return []; const unused = { headers: securityHeaders } } }\n')
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', 'const securityHeaders = ["Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"]\nexport default { async headers() { return [{ source: "/:path*", headers: securityHeaders }] } }\n')
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', 'export default { async headers() { return [{ source: "/:path*", headers: [], decoy: [{ key: "Content-Security-Policy", value: "frame-ancestors self" }, { key: "Referrer-Policy", value: "same-origin" }, { key: "X-Content-Type-Options", value: "nosniff" }] }] } }\n')
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', 'const securityHeaders = [{ key: "Content-Security-Policy", value: "frame-ancestors self" }, { key: "Referrer-Policy", value: "same-origin" }, { key: "X-Content-Type-Options", value: "nosniff" }]\nexport default { async headers() { const securityHeaders = ["Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options"]; return [{ source: "/:path*", headers: securityHeaders }] } }\n')
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    const validHeaders = '[{ key: "Content-Security-Policy", value: "frame-ancestors self" }, { key: "Referrer-Policy", value: "same-origin" }, { key: "X-Content-Type-Options", value: "nosniff" }]'
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] } }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'pass')
    overwrite(root, 'next.config.ts', `const decoy = { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] } }\nexport default { async headers() { return [] } }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { function decoy() { return [{ source: "/:path*", headers: ${validHeaders} }] } return [] } }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `function decoy() { const securityHeaders = ${validHeaders}; return securityHeaders }\nexport default { async headers() { return [{ source: "/:path*", headers: securityHeaders }] } }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, async headers() { return [] } }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `let config = { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] } }; config = { async headers() { return [] } }; export default config\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, headers: undefined }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, headers: async () => [] }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `const headers = undefined; export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, headers }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, "headers": undefined }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, ["headers"]: undefined }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: [{ key: "Content-Security-Policy", value: undefined }, { key: "Referrer-Policy", value: "same-origin" }, { key: "X-Content-Type-Options", value: "nosniff" }] }] }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `const effectiveKey = "headers"; export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, [effectiveKey]: undefined }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, get headers() { return undefined } }\n`)
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')
    overwrite(root, 'next.config.ts', 'export default { async headers() { return [{ source: "/:path*", headers: [{ key: "Content-Security-Policy", value: true }, { key: "Referrer-Policy", value: false }, { key: "X-Content-Type-Options", value: 1 }] }] }\n')
    assert.equal(scan(root).get('edge-security-headers')?.status, 'fail')

    const validTemplate = fs.readFileSync(path.join(root, '.env.example'), 'utf8')
    overwrite(root, '.env.example', validTemplate.replace('RATE_LIMIT_TRUST_PROXY_DEPTH=1', 'RATE_LIMIT_TRUST_PROXY_DEPTH=unbounded'))
    assert.equal(scan(root).get('edge-trusted-proxy-depth')?.status, 'fail')
    overwrite(root, '.env.example', validTemplate.replace(/^APP_ALLOWED_ORIGINS=.*$/m, 'APP_ALLOWED_ORIGINS=*'))
    assert.equal(scan(root).get('edge-allowed-origins')?.status, 'fail')
    overwrite(root, '.env.example', validTemplate)

    overwrite(root, 'docker-compose.yml', 'services:\n  app:\n    image: app:stable\n')
    assert.equal(scan(root).get('release-immutable-artifact')?.status, 'fail')
    overwrite(root, 'docker-compose.yml', '')
    overwrite(root, 'docker-compose.fullapp.yml', 'services:\n  app:\n    volumes: ["/tmp/cache:/tmp/cache"]\n')
    overwrite(root, 'docs/operations.md', 'TLS HTTPS certificate backup restore rollback worker\n')
    assert.equal(scan(root).get('storage-persistent-volume')?.status, 'fail')

    overwrite(root, 'Dockerfile', 'FROM node:24\nRUN npm ci; npm install\nUSER app\n')
    assert.equal(scan(root).get('supply-chain-immutable-install')?.status, 'fail')
    for (const dockerfile of [
      'FROM node:24\nRUN npm ci; npm i\nUSER app\n',
      'FROM node:24\nRUN npm ci; npm update\nUSER app\n',
      'FROM node:24\nRUN npm install; echo npm ci\nUSER app\n',
      'FROM node:24\nRUN npm ci; NODE_ENV=production npm install --omit=dev\nUSER app\n',
      'FROM node:24\nRUN npm ci && (npm install --omit=dev)\nUSER app\n',
      'FROM node:24\nRUN npm ci; npm --silent install\nUSER app\n',
    ]) {
      overwrite(root, 'Dockerfile', dockerfile)
      assert.equal(scan(root).get('supply-chain-immutable-install')?.status, 'fail', dockerfile)
    }
    overwrite(root, 'Dockerfile', 'FROM node:24\nRUN npm install\nUSER app\n')
    overwrite(root, 'scripts/railway-start.sh', 'npm ci\n')
    assert.equal(scan(root).get('supply-chain-immutable-install')?.status, 'fail')

    overwrite(root, 'docker-compose.yml', 'services:\n  app:\n    image: app:one\n  worker:\n    image: worker:two\n    command: yarn mercato worker\n')
    assert.equal(scan(root).get('workers-release-parity')?.status, 'fail')
    overwrite(root, 'docker-compose.yml', 'services:\n  app:\n    image: app:one\n  worker:\n    image: app:one\n    command: yarn mercato worker\n')
    overwrite(root, 'docker-compose.fullapp.yml', 'services:\n  app:\n    image: app:two\n  worker:\n    image: app:two\n    command: yarn mercato worker\n')
    assert.equal(scan(root).get('workers-release-parity')?.status, 'fail')
    overwrite(root, 'docker-compose.yml', 'services:\n  app:\n    image: app:three\n')
    assert.equal(scan(root).get('workers-release-parity')?.status, 'fail')
    overwrite(root, 'docker-compose.yml', 'services:\n  app:\n    image: app:1111111\n  web:\n    image: app:2222222\n  worker:\n    image: app:1111111\n    command: yarn mercato worker\n')
    overwrite(root, 'docker-compose.fullapp.yml', '')
    assert.equal(scan(root).get('workers-release-parity')?.status, 'fail')
    overwrite(root, 'docker-compose.yml', 'services:\n  app:\n    image: app:1111111\n')
    overwrite(root, 'docker-compose.fullapp.yml', 'services:\n  worker:\n    image: app:2222222\n    command: yarn mercato worker\n')
    assert.equal(scan(root).get('workers-release-parity')?.status, 'fail')

    const safeTemplate = 'NODE_ENV=production\nAPP_URL=https://example.com\nDATABASE_URL=\nINTERNAL_APP_ORIGIN=\nPLATFORM_PRIMARY_HOST=\nRATE_LIMIT_TRUST_PROXY_DEPTH=1\nAPP_ALLOWED_ORIGINS=https://example.com\nCACHE_STRATEGY=redis\nREDIS_URL=\n'
    for (const enabled of ['QUERY_ENGINE_DEBUG_SQL=" true "', 'DEMO_MODE=enabled', 'PROFILE_MODE=y']) {
      overwrite(root, '.env.example', `${safeTemplate}${enabled}\n`)
      assert.equal(scan(root).get('runtime-debug-features-disabled')?.status, 'fail', enabled)
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('built CLI accepts expanded IPv6 loopback and inherited non-root stages', () => {
  const root = fixture({
    Dockerfile: 'FROM node:24 AS secure\nRUN yarn install --immutable\nUSER 1001:1001\nFROM secure AS runtime\n',
    'docker-compose.fullapp.yml': 'services:\n  database:\n    image: postgres:17\n    ports:\n      - host_ip: "0:0:0:0:0:0:0:1"\n        target: 5432\n        published: 5432\n',
  })
  try {
    const findings = scan(root)
    assert.equal(findings.get('infrastructure-private-services')?.status, 'pass')
    assert.equal(findings.get('container-non-root-user')?.status, 'pass')
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})
