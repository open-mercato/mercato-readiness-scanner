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
    'services:\n  redis:\n    ports:\n      - "6379:6379"\n',
    'services:\n  database:\n    image: postgres:17\n    ports:\n      - target: 5432\n        published: 5432\n',
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
    ].join('\n'))
    assert.equal(status(root, 'infrastructure-private-services'), 'pass')
  } finally {
    removeFixture(root)
  }
})

test('requires a non-root USER in the final Docker stage', () => {
  const root = makeAppFixture()
  try {
    overwrite(root, 'Dockerfile', 'FROM node:24 AS build\nUSER app\nFROM node:24\nCOPY --from=build /app /app\n')
    assert.equal(status(root, 'container-non-root-user'), 'fail')
    overwrite(root, 'Dockerfile', 'FROM node:24 AS build\nUSER root\nFROM node:24\nUSER app\n')
    assert.equal(status(root, 'container-non-root-user'), 'pass')
  } finally {
    removeFixture(root)
  }
})

test('counts only active blocking workflow commands as release validation', () => {
  const root = makeAppFixture()
  try {
    overwrite(root, '.github/workflows/release.yml', [
      'jobs:',
      '  validate:',
      '    steps:',
      '      # yarn generate && yarn build && yarn test && yarn db:migrate',
      '      - run: echo no-op',
    ].join('\n'))
    assert.equal(status(root, 'release-validation-gate'), 'fail')

    overwrite(root, '.github/workflows/release.yml', [
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
    fs.appendFileSync(path.join(root, '.env.example'), 'DEBUG_MODE=true\n')
    assert.equal(status(root, 'runtime-debug-features-disabled'), 'fail')
  } finally {
    removeFixture(root)
  }
})

test('rejects Node engine ranges with any unsupported alternative', () => {
  const root = makeAppFixture()
  try {
    const packagePath = path.join(root, 'package.json')
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8')) as { engines: { node: string } }
    for (const range of ['>=24', '^24.0.0', '24.x', '>=24 <27']) {
      packageJson.engines.node = range
      fs.writeFileSync(packagePath, JSON.stringify(packageJson))
      assert.equal(status(root, 'runtime-supported-node'), 'pass', range)
    }
    for (const range of ['>=18 <19 || >=24', '>=18', '<25', '23.x']) {
      packageJson.engines.node = range
      fs.writeFileSync(packagePath, JSON.stringify(packageJson))
      assert.equal(status(root, 'runtime-supported-node'), 'fail', range)
    }
  } finally {
    removeFixture(root)
  }
})
