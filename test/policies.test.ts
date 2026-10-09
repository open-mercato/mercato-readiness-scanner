import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { scan } from '../src/scan.js'
import type { FindingStatus } from '../src/types.js'
import { makeAppFixture, removeFixture } from './fixture.js'

function overwrite(root: string, relativePath: string, contents: string): void {
  const destination = path.join(root, relativePath)
  fs.mkdirSync(path.dirname(destination), { recursive: true })
  fs.writeFileSync(destination, contents)
}

function status(root: string, id: string): FindingStatus | undefined {
  return scan(root).results.find((result) => result.id === id)?.status
}

test('detects public Compose bindings across inline, short, long, and image-identified services', () => {
  const variants = [
    'services:\n  postgres:\n    ports: ["5432:5432"]\n',
    'services:\n    postgres:\n        ports: ["5432:5432"]\n',
    'services:\n  redis:\n    ports:\n      - "6379:6379"\n',
    'services:\n    redis:\n        ports:\n            - "6379:6379"\n',
    'services:\n  database:\n    image: postgres:17\n    ports:\n      - target: 5432\n        published: 5432\n',
    'services:\n    database:\n        image: postgres:17\n        ports:\n            - target: 5432\n              published: 5432\n',
  ]
  for (const source of variants) {
    const root = makeAppFixture()
    try {
      overwrite(root, 'docker-compose.fullapp.yml', source)
      assert.equal(status(root, 'infrastructure-private-services'), 'fail', source)
    } finally {
      removeFixture(root)
    }
  }
})

test('accepts only explicit loopback Compose bindings for recognized stateful services', () => {
  const root = makeAppFixture()
  try {
    overwrite(root, 'docker-compose.fullapp.yml', [
      'services:',
      '  postgres:',
      '    ports:',
      '      - "127.0.0.1:5432:5432"',
      '  redis:',
      '    ports: ["[::1]:6379:6379"]',
      '  search:',
      '    ports:',
      '      - target: 9200',
      '        published: 9200',
      '        host_ip: 127.0.0.1',
      '  database:',
      '    image: postgres:17',
      '    ports:',
      '      - host_ip: "::1"',
      '        published: 5432',
      '        target: 5432',
      '  cache:',
      '    image: redis:7',
      '    ports: ["[0:0:0:0:0:0:0:1]:6379:6379"]',
    ].join('\n'))
    assert.equal(status(root, 'infrastructure-private-services'), 'pass')
  } finally {
    removeFixture(root)
  }
})

test('evaluates effective Compose merges and host networking', () => {
  const root = makeAppFixture()
  try {
    overwrite(root, 'docker-compose.fullapp.yml', [
      'x-database: &database',
      '  image: postgres:17',
      '  ports: ["5432:5432"]',
      'services:',
      '  database:',
      '    <<: *database',
    ].join('\n'))
    assert.equal(status(root, 'infrastructure-private-services'), 'fail')
    overwrite(root, 'docker-compose.fullapp.yml', 'services:\n  redis:\n    image: redis:7\n    network_mode: host\n')
    assert.equal(status(root, 'infrastructure-private-services'), 'fail')
  } finally {
    removeFixture(root)
  }
})

test('requires a non-root USER in the final Docker stage', () => {
  const root = makeAppFixture()
  try {
    overwrite(root, 'Dockerfile', 'FROM node:24 AS build\nUSER app\nFROM node:24\nCOPY --from=build /app /app\n')
    assert.equal(status(root, 'container-non-root-user'), 'fail')
    overwrite(root, 'Dockerfile', 'FROM node:24\nUSER root:root\n')
    assert.equal(status(root, 'container-non-root-user'), 'fail')
    overwrite(root, 'Dockerfile', 'FROM node:24\nUSER 0:0\n')
    assert.equal(status(root, 'container-non-root-user'), 'fail')
    overwrite(root, 'Dockerfile', 'FROM node:24 AS build\nUSER root\nFROM node:24\nUSER app\n')
    assert.equal(status(root, 'container-non-root-user'), 'pass')
    overwrite(root, 'Dockerfile', 'FROM node:24 AS secure\nUSER 1001:1001\nFROM secure AS runtime\n')
    assert.equal(status(root, 'container-non-root-user'), 'pass')
  } finally {
    removeFixture(root)
  }
})

test('counts only active blocking workflow commands as release validation', () => {
  const root = makeAppFixture()
  try {
    overwrite(root, '.github/workflows/release.yml', [
      'on:',
      '  push:',
      'jobs:',
      '  validate:',
      '    steps:',
      '      # yarn generate && yarn build && yarn test && yarn db:migrate',
      '      - run: echo no-op',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'fail')

    for (const testCommand of ['yarn test; true', 'yarn test\n          true', 'yarn test | tee test.log']) {
      overwrite(root, '.github/workflows/release.yml', [
        'on:',
        '  push:',
        'jobs:',
        '  validate:',
        '    steps:',
        '      - run: yarn generate',
        '      - run: yarn build',
        '      - shell: bash {0}',
        '        run: |',
        `          ${testCommand}`,
        '      - run: yarn db:migrate --check',
      ].join('\n'))
      assert.equal(status(root, 'release-validation-gate'), 'fail', testCommand)
    }

    for (const shell of [null, 'bash -e {0}']) {
      overwrite(root, '.github/workflows/release.yml', [
        'on:',
        '  push:',
        'jobs:',
        '  validate:',
        '    steps:',
        '      - run: yarn generate',
        '      - run: yarn build',
        ...(shell ? [`      - shell: ${shell}`, '        run: yarn test & true'] : ['      - run: yarn test & true']),
        '      - run: yarn db:migrate --check',
      ].join('\n'))
      assert.equal(status(root, 'release-validation-gate'), 'fail', shell ?? 'default shell')
    }

    overwrite(root, '.github/workflows/release.yml', [
      'on:',
      '  push:',
      'jobs:',
      '  validate:',
      '    steps:',
      '      - run: yarn generate',
      '      - run: yarn build',
      '      - run: yarn test || true',
      '      - run: yarn db:migrate --check',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'fail')

    overwrite(root, '.github/workflows/release.yml', [
      'on:',
      '  push:',
      'jobs:',
      '  validate:',
      '    steps:',
      '      - run: yarn generate',
      '      - run: yarn build',
      '      - run: yarn test',
      '      - run: yarn db:migrate --check',
      '        continue-on-error: ${{ matrix.nonblocking }}',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'fail')

    overwrite(root, '.github/workflows/release.yml', [
      'on:',
      '  push:',
      'jobs:',
      '  validate:',
      '    steps:',
      '      - run: yarn generate',
      '      - run: yarn build',
      '      - run: yarn test',
      '        continue-on-error: "${{ true }}"',
      '      - if: "${{ false }}"',
      '        run: yarn db:migrate --check',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'fail')

    overwrite(root, '.github/workflows/release.yml', [
      'on:',
      '  push:',
      'jobs:',
      '  validate:',
      '    steps:',
      '      - if: false',
      '        run: yarn generate',
      '      - run: yarn build',
      '      - continue-on-error: true',
      '        run: yarn test',
      '      - run: yarn db:migrate --check',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'fail')

    overwrite(root, '.github/workflows/release.yml', [
      'on:',
      '  push:',
      'jobs:',
      '  validate:',
      '    steps:',
      '      - run: yarn generate',
      '      - run: yarn build',
      '      - run: yarn test',
      '      - run: yarn db:migrate --check',
      '    continue-on-error: ${{ true }}',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'fail')

    overwrite(root, '.github/workflows/release.yml', [
      'on:',
      '  push:',
      'jobs:',
      '  validate:',
      '    steps:',
      '      - run: |',
      '          yarn generate',
      '          yarn build',
      '      - run: yarn test',
      '        continue-on-error: true',
      '      - run: yarn db:migrate --check',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'fail')

    overwrite(root, '.github/workflows/release.yml', [
      'on:',
      '  pull_request:',
      'jobs:',
      '  validate:',
      '    steps:',
      '      - run: yarn generate',
      '      - run: yarn build',
      '      - run: yarn test',
      '      - run: yarn db:migrate --check',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'fail')

    for (const trigger of [
      ['  workflow_dispatch:'],
      ['  workflow_call:'],
      ['  push:', '    branches: [feature-only]'],
      ['  push:', '    branches: [feature/**]'],
      ['  push:', '    tags: [feature-*]'],
      ['  release:', '    types: [deleted]'],
      ['  push:', '    branches: [main]', '    paths-ignore: ["**"]'],
      ['  push:', '    branches-ignore: [main, master, develop]'],
      ['  push:', '    branches-ignore: [ma*]'],
    ]) {
      overwrite(root, '.github/workflows/release.yml', [
        'on:',
        ...trigger,
        'jobs:',
        '  validate:',
        '    steps:',
        '      - run: yarn generate',
        '      - run: yarn build',
        '      - run: yarn test',
        '      - run: yarn db:migrate --check',
      ].join('\n'))
      assert.equal(status(root, 'release-validation-gate'), 'fail', trigger.join(' '))
    }

    overwrite(root, '.github/workflows/release.yml', [
      'on:',
      '  push:',
      '    branches: [main]',
      'jobs:',
      '  validate:',
      '    steps:',
      '      - run: |',
      "          cat <<'COMMANDS'",
      '          yarn generate',
      '          yarn build',
      '          yarn test',
      '          yarn db:migrate --check',
      '          COMMANDS',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'fail')

    overwrite(root, '.github/workflows/release.yml', [
      'on:',
      '  push:',
      'jobs:',
      '  build:',
      '    steps:',
      '      - run: yarn generate',
      '      - run: yarn build',
    ].join('\n'))
    overwrite(root, '.github/workflows/other.yml', [
      'on:',
      '  push:',
      'jobs:',
      '  verify:',
      '    steps:',
      '      - run: yarn test',
      '      - run: yarn db:migrate --check',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'fail')
    fs.rmSync(path.join(root, '.github/workflows/other.yml'))

    overwrite(root, '.github/workflows/release.yml', [
      'on:',
      '  push:',
      'jobs:',
      '  validate:',
      '    steps:',
      '      - run: yarn generate',
      '      - run: yarn build',
      '      - run: yarn test',
      '      - run: yarn db:migrate --check',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'pass')
  } finally {
    removeFixture(root)
  }
})

test('treats only explicitly enabled development switches as unsafe defaults', () => {
  const root = makeAppFixture()
  try {
    fs.appendFileSync(path.join(root, '.env.example'), '\nAUTOLOGIN_ENABLED=false\nAUTOLOGIN_TOKEN=\n')
    assert.equal(status(root, 'runtime-debug-features-disabled'), 'warning')
    fs.appendFileSync(path.join(root, '.env.example'), 'DEBUG_MODE="false"\nPROFILE_MODE=\'false\'\n')
    assert.equal(status(root, 'runtime-debug-features-disabled'), 'warning')
    const template = fs.readFileSync(path.join(root, '.env.example'), 'utf8')
    for (const enabled of ['QUERY_ENGINE_DEBUG_SQL=" true "', 'DEMO_MODE=enabled', 'PROFILE_MODE=y']) {
      fs.writeFileSync(path.join(root, '.env.example'), `${template}\n${enabled}\n`)
      assert.equal(status(root, 'runtime-debug-features-disabled'), 'fail', enabled)
    }
  } finally {
    removeFixture(root)
  }
})

test('requires effective worker and command evidence instead of comments or empty files', () => {
  const root = makeAppFixture()
  try {
    overwrite(root, 'railway.worker.toml', '')
    overwrite(root, 'docker-compose.fullapp.yml', 'services:\n  app:\n    image: app:abcdef1\n')
    assert.equal(status(root, 'operations-worker-topology'), 'fail')
    assert.equal(status(root, 'workers-release-parity'), 'skipped')

    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as { scripts: Record<string, string> }
    manifest.scripts.build = 'echo NODE_ENV=production && next build'
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest))
    assert.equal(status(root, 'runtime-production-scripts'), 'fail')
    manifest.scripts.build = 'NODE_ENV=production next build || true'
    manifest.scripts.start = 'next start'
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest))
    assert.equal(status(root, 'runtime-production-scripts'), 'fail')
    manifest.scripts.build = 'NODE_ENV=production next build'
    manifest.scripts.start = 'next dev'
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest))
    assert.equal(status(root, 'runtime-production-scripts'), 'fail')
    for (const scripts of [
      { build: 'NODE_ENV=production next build --help', start: 'next start' },
      { build: 'NODE_ENV=production next build', start: 'next start --help' },
      { build: 'NODE_ENV=production next build --help=true', start: 'next start' },
      { build: 'NODE_ENV=production next build', start: 'next start --version=true' },
      { build: 'NODE_ENV=production next build -h=true', start: 'next start' },
      { build: 'NODE_ENV=production next build', start: 'next start -v=true' },
    ]) {
      manifest.scripts = scripts
      fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest))
      assert.equal(status(root, 'runtime-production-scripts'), 'fail')
    }

    const baselineIgnore = fs.readFileSync(path.join(root, '.gitignore'), 'utf8')
    overwrite(root, '.gitignore', `${baselineIgnore}\n!.env.production\n!*.pem\n!.env.[p]roduction\n!/.env.staging\n`)
    assert.equal(status(root, 'secrets-ignore-policy'), 'fail')
    overwrite(root, '.gitignore', baselineIgnore)

    const baselineTemplate = fs.readFileSync(path.join(root, '.env.example'), 'utf8')
    overwrite(root, '.env.example', baselineTemplate.replace('DATABASE_URL=', 'DATABASE_URL=postgres://operator:live-password@database.internal/app'))
    assert.equal(status(root, 'runtime-env-template'), 'fail')
    overwrite(root, '.env.example', baselineTemplate.replace('DATABASE_URL=', 'DATABASE_URL=postgres://example.com/app?password=live-secret'))
    assert.equal(status(root, 'runtime-env-template'), 'fail')
    overwrite(root, '.env.example', baselineTemplate.replace('DATABASE_URL=', 'DATABASE_URL="postgres://example.com/app#token=percent%2Dencoded%2Dsecret"'))
    assert.equal(status(root, 'runtime-env-template'), 'fail')
    for (const value of [
      'postgres://example.com/app?sslpassword=live-secret',
      'postgres://example.com/app?apiKey=live-secret',
      'postgres://example.com/app?pwd=live-secret',
      'postgres://example.com/app#opaque-live-secret',
    ]) {
      overwrite(root, '.env.example', baselineTemplate.replace('DATABASE_URL=', `DATABASE_URL="${value}"`))
      assert.equal(status(root, 'runtime-env-template'), 'fail', value)
    }
    overwrite(root, '.env.example', baselineTemplate)

    overwrite(root, 'next.config.ts', 'const active = true // Content-Security-Policy Referrer-Policy X-Content-Type-Options X-Frame-Options\nexport default { active }\n')
    assert.equal(status(root, 'edge-security-headers'), 'fail')

    overwrite(root, 'Dockerfile', 'FROM node:24\nRUN echo preparing # npm ci\nRUN npm install\nUSER app\n')
    assert.equal(status(root, 'supply-chain-immutable-install'), 'fail')

    overwrite(root, 'railway.worker.toml', '[deploy]\nstartCommand = "echo worker"\n')
    assert.equal(status(root, 'operations-worker-topology'), 'fail')

    overwrite(root, 'railway.worker.toml', '[deploy]\nstartCommand = "npm worker"\n')
    assert.equal(status(root, 'operations-worker-topology'), 'fail')
    for (const command of ['yarn mercato worker || true', 'yarn mercato worker --help']) {
      overwrite(root, 'railway.worker.toml', `[deploy]\nstartCommand = "${command}"\n`)
      assert.equal(status(root, 'operations-worker-topology'), 'fail', command)
    }
    overwrite(root, 'railway.worker.toml', '[deploy]\nstartCommand = "npm run worker"\n')
    assert.equal(status(root, 'operations-worker-topology'), 'fail')
    const workerManifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as { scripts: Record<string, string> }
    workerManifest.scripts.worker = 'mercato worker'
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(workerManifest))
    assert.equal(status(root, 'operations-worker-topology'), 'pass')

    overwrite(root, 'railway.toml', '[deploy]\nstartCommand = "echo /api/healthz && echo yarn db:migrate"\n')
    assert.equal(status(root, 'operations-health-check'), 'fail')
    assert.equal(status(root, 'release-database-migrations'), 'fail')
    overwrite(root, 'railway.toml', '[build]\nhealthcheckPath = "/api/healthz"\nstartCommand = "yarn db:migrate"\n[deploy]\nstartCommand = "false && yarn db:migrate"\n')
    assert.equal(status(root, 'operations-health-check'), 'fail')
    assert.equal(status(root, 'release-database-migrations'), 'fail')
    for (const healthcheck of [
      'healthcheck:\n      disable: true\n      test: ["CMD", "curl", "http://localhost:3000/api/healthz"]',
      'healthcheck:\n      test: ["CMD-SHELL", "echo curl http://localhost:3000/api/healthz"]',
      'healthcheck:\n      test: ["CMD-SHELL", "curl http://localhost:3000/api/healthz || true"]',
    ]) {
      overwrite(root, 'docker-compose.fullapp.yml', `services:\n  app:\n    ${healthcheck}\n`)
      assert.equal(status(root, 'operations-health-check'), 'fail', healthcheck)
    }

    overwrite(root, 'railway.worker.toml', '[deploy]\nstartCommand = "yarn mercato worker"\n')
    overwrite(root, 'docker-compose.fullapp.yml', [
      'services:',
      '  app:',
      '    image: app:abcdef1',
      '  worker:',
      '    image: worker:fedcba9',
      '    command: yarn mercato worker',
    ].join('\n'))
    assert.equal(status(root, 'workers-release-parity'), 'fail')

    overwrite(root, 'next.config.ts', 'const unused = "Content-Security-Policy Referrer-Policy X-Content-Type-Options X-Frame-Options"\nexport default {}\n')
    assert.equal(status(root, 'edge-security-headers'), 'fail')

    overwrite(root, 'next.config.ts', 'const unused = ["Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"]\nexport default { async headers() { return [] } }\n')
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', 'const securityHeaders = ["Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"]\nexport default { async headers() { return []; const unused = { headers: securityHeaders } } }\n')
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', 'const securityHeaders = ["Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"]\nexport default { async headers() { return [{ source: "/:path*", headers: securityHeaders }] } }\n')
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', 'export default { async headers() { return [{ source: "/:path*", headers: [], decoy: [{ key: "Content-Security-Policy", value: "frame-ancestors self" }, { key: "Referrer-Policy", value: "same-origin" }, { key: "X-Content-Type-Options", value: "nosniff" }] }] } }\n')
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', 'const securityHeaders = [{ key: "Content-Security-Policy", value: "frame-ancestors self" }, { key: "Referrer-Policy", value: "same-origin" }, { key: "X-Content-Type-Options", value: "nosniff" }]\nexport default { async headers() { const securityHeaders = ["Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options"]; return [{ source: "/:path*", headers: securityHeaders }] } }\n')
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    const validHeaders = '[{ key: "Content-Security-Policy", value: "frame-ancestors self" }, { key: "Referrer-Policy", value: "same-origin" }, { key: "X-Content-Type-Options", value: "nosniff" }]'
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] } }\n`)
    assert.equal(status(root, 'edge-security-headers'), 'pass')
    overwrite(root, 'next.config.ts', `const decoy = { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] } }\nexport default { async headers() { return [] } }\n`)
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { function decoy() { return [{ source: "/:path*", headers: ${validHeaders} }] } return [] } }\n`)
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', `function decoy() { const securityHeaders = ${validHeaders}; return securityHeaders }\nexport default { async headers() { return [{ source: "/:path*", headers: securityHeaders }] } }\n`)
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, async headers() { return [] } }\n`)
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', `let config = { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] } }; config = { async headers() { return [] } }; export default config\n`)
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, headers: undefined }\n`)
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, headers: async () => [] }\n`)
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', `const headers = undefined; export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, headers }\n`)
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, "headers": undefined }\n`)
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: ${validHeaders} }] }, ["headers"]: undefined }\n`)
    assert.equal(status(root, 'edge-security-headers'), 'fail')
    overwrite(root, 'next.config.ts', `export default { async headers() { return [{ source: "/:path*", headers: [{ key: "Content-Security-Policy", value: undefined }, { key: "Referrer-Policy", value: "same-origin" }, { key: "X-Content-Type-Options", value: "nosniff" }] }] }\n`)
    assert.equal(status(root, 'edge-security-headers'), 'fail')

    overwrite(root, 'Dockerfile', 'FROM node:24\nRUN npm ci; npm install\nUSER app\n')
    assert.equal(status(root, 'supply-chain-immutable-install'), 'fail')

    for (const dockerfile of [
      'FROM node:24\nRUN npm ci; npm i\nUSER app\n',
      'FROM node:24\nRUN npm ci; npm update\nUSER app\n',
      'FROM node:24\nRUN npm install; echo npm ci\nUSER app\n',
      'FROM node:24\nRUN npm ci; NODE_ENV=production npm install --omit=dev\nUSER app\n',
      'FROM node:24\nRUN npm ci && (npm install --omit=dev)\nUSER app\n',
      'FROM node:24\nRUN npm ci; npm --silent install\nUSER app\n',
    ]) {
      overwrite(root, 'Dockerfile', dockerfile)
      assert.equal(status(root, 'supply-chain-immutable-install'), 'fail', dockerfile)
    }

    overwrite(root, 'Dockerfile', 'FROM node:24\nRUN npm install\nUSER app\n')
    overwrite(root, 'scripts/railway-start.sh', 'npm ci\n')
    assert.equal(status(root, 'supply-chain-immutable-install'), 'fail')

    overwrite(root, 'docker-compose.yml', 'services:\n  app:\n    image: app:one\n  worker:\n    image: worker:two\n    command: yarn mercato worker\n')
    assert.equal(status(root, 'workers-release-parity'), 'fail')

    overwrite(root, 'docker-compose.yml', 'services:\n  app:\n    image: app:one\n  worker:\n    image: app:one\n    command: yarn mercato worker\n')
    overwrite(root, 'docker-compose.fullapp.yml', 'services:\n  app:\n    image: app:two\n  worker:\n    image: app:two\n    command: yarn mercato worker\n')
    assert.equal(status(root, 'workers-release-parity'), 'fail')

    overwrite(root, 'docker-compose.yml', 'services:\n  app:\n    image: app:three\n')
    assert.equal(status(root, 'workers-release-parity'), 'fail')

    overwrite(root, 'docker-compose.yml', 'services:\n  app:\n    image: app:1111111\n  web:\n    image: app:2222222\n  worker:\n    image: app:1111111\n    command: yarn mercato worker\n')
    overwrite(root, 'docker-compose.fullapp.yml', '')
    assert.equal(status(root, 'workers-release-parity'), 'fail')

    overwrite(root, 'docker-compose.yml', 'services:\n  app:\n    image: app:1111111\n')
    overwrite(root, 'docker-compose.fullapp.yml', 'services:\n  worker:\n    image: app:2222222\n    command: yarn mercato worker\n')
    assert.equal(status(root, 'workers-release-parity'), 'fail')
  } finally {
    removeFixture(root)
  }
})

test('rejects Node engine ranges with any unsupported alternative', () => {
  const root = makeAppFixture()
  try {
    const packagePath = path.join(root, 'package.json')
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8')) as { engines: { node: string } }
    for (const range of ['>=24', '>23', '>23.x', '^24.0.0', '24.x', '=24.0.0', '24.0.0 - 26.0.0', '>=24 <27', '24 || >=26']) {
      packageJson.engines.node = range
      fs.writeFileSync(packagePath, JSON.stringify(packageJson))
      assert.equal(status(root, 'runtime-supported-node'), 'pass', range)
    }
    for (const range of ['>=18 <19 || >=24', '>=18', '<25', '23.x', '*', 'not-a-range', '24 ||', '|| 24', '24 || || 26']) {
      packageJson.engines.node = range
      fs.writeFileSync(packagePath, JSON.stringify(packageJson))
      assert.equal(status(root, 'runtime-supported-node'), 'fail', range)
    }
  } finally {
    removeFixture(root)
  }
})
