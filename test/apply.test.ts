import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { RULES } from '../src/rules.js'
import { scan } from '../src/scan.js'
import { commitFixture, DEFAULT_FIXTURE_FILES, fixtureStatus, makeAppFixture, makeCezarRunStub, makeReportDirectory, removeFixture } from './fixture.js'

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const cli = path.join(repositoryRoot, 'src', 'cli.ts')

const SAFE_AUTOFIXABLE = ['data-backup-restore-runbook', 'release-rollback-runbook', 'runtime-production-scripts', 'secrets-ignore-policy']

function run(args: string[], timeout = 60_000) {
  return spawnSync(process.execPath, ['--import', 'tsx', cli, ...args], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    timeout,
  })
}

function manifest(scripts: Record<string, string> | null): string {
  const parsed = JSON.parse(DEFAULT_FIXTURE_FILES['package.json'] ?? '{}') as Record<string, unknown>
  if (scripts === null) delete parsed.scripts
  else parsed.scripts = scripts
  return JSON.stringify(parsed, null, 2)
}

/** A fixture whose four safely fixable rules fail, plus two manual-only rules that must not be touched. */
function brokenFiles(scripts: Record<string, string> | null = null): Record<string, string | null> {
  return {
    '.gitignore': '.env\n',
    'package.json': manifest(scripts),
    'docs/operations.md': null,
    '.env.example': (DEFAULT_FIXTURE_FILES['.env.example'] ?? '').split('\n').filter((line) => !line.startsWith('PLATFORM_PRIMARY_HOST')).join('\n'),
  }
}

function read(root: string, relativePath: string): string {
  return fs.readFileSync(path.join(root, relativePath), 'utf8')
}

function statuses(root: string): Map<string, string> {
  return new Map(scan(root).results.map((result) => [result.id, result.status]))
}

test('every rule is deliberately classified as safe-autofixable or manual-only', () => {
  for (const rule of RULES) {
    if (rule.autofix.safety === 'manual-only') assert.ok(rule.autofix.reason.length > 30, `${rule.id} needs a real manual-only reason`)
    else assert.ok(rule.autofix.summary.length > 20, `${rule.id} needs a real autofix summary`)
  }
  assert.deepEqual(RULES.filter((rule) => rule.autofix.safety === 'safe-additive').map((rule) => rule.id).sort(), SAFE_AUTOFIXABLE)
})

test('the apply classification stays out of the versioned report contract', () => {
  const root = makeAppFixture()
  try {
    const report = scan(root)
    for (const result of report.results) {
      assert.deepEqual(Object.keys(result).sort(), ['category', 'docsUrl', 'evidence', 'id', 'remediation', 'severity', 'status', 'summary', 'title'])
    }
    assert.equal(report.schemaVersion, 1)
  } finally {
    removeFixture(root)
  }
})

test('refuses to apply anything outside a git working tree', () => {
  const root = makeAppFixture({ files: brokenFiles(), git: 'none' })
  try {
    const before = read(root, '.gitignore')
    const result = run(['apply', root, '--yes', '--no-color'])
    assert.equal(result.status, 2, result.stderr)
    assert.match(result.stderr, /is not a git working tree/)
    assert.match(result.stderr, /git init/)
    assert.equal(read(root, '.gitignore'), before)
    assert.equal(fs.existsSync(path.join(root, 'docs/runbooks')), false)
  } finally {
    removeFixture(root)
  }
})

test('refuses a dirty worktree unless the override flag is passed', () => {
  const root = makeAppFixture({ files: brokenFiles(), git: 'init' })
  try {
    const refused = run(['apply', root, '--yes', '--no-color'])
    assert.equal(refused.status, 2, refused.stderr)
    assert.match(refused.stderr, /uncommitted changes/)
    assert.match(refused.stderr, /--allow-dirty/)
    assert.equal(read(root, '.gitignore'), '.env\n')

    const allowed = run(['apply', root, '--yes', '--allow-dirty', '--no-color'])
    assert.equal(allowed.status, 0, allowed.stderr)
    assert.match(read(root, '.gitignore'), /\.npmrc/)
  } finally {
    removeFixture(root)
  }
})

test('applies every safe policy, writes correct files, and leaves manual-only policies untouched', () => {
  const root = makeAppFixture({ files: brokenFiles(), git: 'commit' })
  try {
    const envTemplateBefore = read(root, '.env.example')
    const nextConfigBefore = read(root, 'next.config.ts')
    const before = statuses(root)
    assert.equal(before.get('secrets-ignore-policy'), 'fail')
    assert.equal(before.get('runtime-production-scripts'), 'fail')
    assert.equal(before.get('data-backup-restore-runbook'), 'fail')
    assert.equal(before.get('release-rollback-runbook'), 'fail')
    assert.equal(before.get('runtime-env-template'), 'fail')
    assert.equal(before.get('edge-tls-and-canonical-origin'), 'fail')

    const result = run(['apply', root, '--yes', '--no-color'])
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stderr, '')

    const ignore = read(root, '.gitignore')
    assert.match(ignore, /^\.env$/m)
    for (const pattern of ['.env.production', '.env.local', '.env.*.local', '*.pem', '*.key', '.mcp.json', '.npmrc', '.ai/session-exports/']) {
      assert.ok(ignore.split('\n').includes(pattern), `missing ${pattern}`)
    }
    assert.match(ignore, /# Added by mercato-readiness apply/)

    const updated = JSON.parse(read(root, 'package.json')) as { name: string, scripts: Record<string, string>, dependencies: Record<string, string> }
    assert.equal(updated.scripts.build, 'NODE_ENV=production next build')
    assert.equal(updated.scripts.start, 'mercato server start')
    assert.equal(updated.name, 'readiness-fixture')
    assert.equal(Object.keys(updated.dependencies).length, 4)

    assert.match(read(root, 'docs/runbooks/backup-and-restore.md'), /# Backup and restore runbook/)
    assert.match(read(root, 'docs/runbooks/backup-and-restore.md'), /TODO: named owner accountable for restores/)
    assert.match(read(root, 'docs/runbooks/rollback-and-forward-fix.md'), /# Rollback and forward-fix runbook/)

    const after = statuses(root)
    for (const id of SAFE_AUTOFIXABLE) assert.notEqual(after.get(id), 'fail', `${id} should no longer fail`)

    // Manual-only rules: nothing was written for them, and they are reported with their docs URL.
    assert.equal(read(root, '.env.example'), envTemplateBefore)
    assert.equal(read(root, 'next.config.ts'), nextConfigBefore)
    assert.equal(after.get('runtime-env-template'), 'fail')
    assert.equal(after.get('edge-tls-and-canonical-origin'), 'fail')
    assert.equal(fs.existsSync(path.join(root, 'src/app/api/healthz')), false)
    assert.match(result.stdout, /Skipped \(manual only\)/)
    assert.match(result.stdout, /runtime-env-template/)
    assert.match(result.stdout, /docs\/rules\/runtime-env-template\.md/)
    assert.match(result.stdout, /never writes any \.env\* file/)
  } finally {
    removeFixture(root)
  }
})

test('never rewrites an existing script value', () => {
  const root = makeAppFixture({ files: brokenFiles({ build: 'next build' }), git: 'commit' })
  try {
    const result = run(['apply', root, '--yes', '--no-color'])
    assert.equal(result.status, 0, result.stderr)
    const updated = JSON.parse(read(root, 'package.json')) as { scripts: Record<string, string> }
    assert.equal(updated.scripts.build, 'next build')
    assert.equal(updated.scripts.start, 'mercato server start')
    // The remaining half of the rule needs a manual edit, so it is still reported as failing.
    assert.equal(statuses(root).get('runtime-production-scripts'), 'fail')
  } finally {
    removeFixture(root)
  }
})

test('restores ignore coverage that a later negation re-includes', () => {
  // The check tests *effective* gitignore coverage, so a pattern that is listed and then
  // re-included by a later negation is still a finding. The autofix has to see the same thing:
  // filtering on raw pattern presence would report nothing to fix while the rule kept failing.
  const files = { ...brokenFiles(), '.gitignore': '.env\n.env.local\n!.env\n' }
  const root = makeAppFixture({ files, git: 'commit' })
  try {
    assert.equal(statuses(root).get('secrets-ignore-policy'), 'fail')

    const result = run(['apply', root, '--yes', '--no-color'])
    assert.equal(result.status, 0, result.stderr)

    // Appended, never rewritten: the operator's own three lines survive byte-for-byte at the top.
    const ignore = read(root, '.gitignore')
    assert.ok(ignore.startsWith('.env\n.env.local\n!.env\n'), ignore)
    // And the re-appended pattern lands after the negation, so last-match-wins makes it effective.
    const lines = ignore.split('\n')
    assert.ok(lines.lastIndexOf('.env') > lines.indexOf('!.env'), ignore)
    assert.equal(statuses(root).get('secrets-ignore-policy'), 'pass')

    // And it converges: a second pass has nothing left to do.
    commitFixture(root, 'restore ignore coverage')
    const again = run(['apply', root, '--yes', '--no-color'])
    assert.equal(again.status, 0, again.stderr)
    assert.match(again.stdout, /0 change\(s\) written/)
  } finally {
    removeFixture(root)
  }
})

test('a second apply is a no-op', () => {
  const root = makeAppFixture({ files: brokenFiles(), git: 'commit' })
  try {
    assert.equal(run(['apply', root, '--yes', '--no-color']).status, 0)
    const ignoreAfterFirst = read(root, '.gitignore')
    const manifestAfterFirst = read(root, 'package.json')
    const runbookAfterFirst = read(root, 'docs/runbooks/backup-and-restore.md')
    const statusAfterFirst = fixtureStatus(root)

    // Immediately, over the still-dirty worktree the first apply produced.
    const again = run(['apply', root, '--yes', '--allow-dirty', '--no-color'])
    assert.equal(again.status, 0, again.stderr)
    assert.match(again.stdout, /0 change\(s\) written/)
    assert.equal(fixtureStatus(root), statusAfterFirst)

    // And through the real workflow: review, commit, re-run on a clean worktree.
    commitFixture(root, 'apply safe readiness policies')
    const third = run(['apply', root, '--yes', '--no-color'])
    assert.equal(third.status, 0, third.stderr)
    assert.match(third.stdout, /0 change\(s\) written/)
    assert.equal(fixtureStatus(root), '')
    assert.equal(read(root, '.gitignore'), ignoreAfterFirst)
    assert.equal(read(root, 'package.json'), manifestAfterFirst)
    assert.equal(read(root, 'docs/runbooks/backup-and-restore.md'), runbookAfterFirst)
  } finally {
    removeFixture(root)
  }
})

test('errors instead of prompting when stdin is not a TTY, and succeeds with the explicit flag', () => {
  const root = makeAppFixture({ files: brokenFiles(), git: 'commit' })
  try {
    const refused = run(['apply', root, '--no-color'], 30_000)
    assert.equal(refused.signal, null, 'the CLI must not hang waiting for an answer')
    assert.equal(refused.status, 2, refused.stderr)
    assert.match(refused.stderr, /stdin or stdout is not a TTY/)
    assert.match(refused.stderr, /--yes/)
    assert.equal(read(root, '.gitignore'), '.env\n')
    assert.equal(fs.existsSync(path.join(root, 'docs/runbooks')), false)

    const accepted = run(['apply', root, '--non-interactive', '--no-color'])
    assert.equal(accepted.status, 0, accepted.stderr)
    assert.ok(fs.existsSync(path.join(root, 'docs/runbooks/rollback-and-forward-fix.md')))
  } finally {
    removeFixture(root)
  }
})

test('a dry run reports the plan and writes nothing', () => {
  const root = makeAppFixture({ files: brokenFiles(), git: 'commit' })
  try {
    const result = run(['apply', root, '--dry-run', '--no-color'])
    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, /Dry run: nothing was written/)
    assert.match(result.stdout, /change\(s\) planned/)
    assert.equal(fixtureStatus(root), '')
    assert.equal(read(root, '.gitignore'), '.env\n')
  } finally {
    removeFixture(root)
  }
})

test('agent mode builds a prompt that references the saved report and never spawns a real agent', () => {
  const root = makeAppFixture({ files: brokenFiles(), git: 'commit' })
  const stub = makeCezarRunStub()
  const reportDirectory = makeReportDirectory()
  const reportPath = path.join(reportDirectory, 'readiness.md')
  try {
    const printed = run(['apply', root, '--mode', 'agent', '--markdown', reportPath, '--print-prompt', '--no-color'])
    assert.equal(printed.status, 0, printed.stderr)
    assert.match(printed.stdout, /^# Task: apply Open Mercato production-readiness remediations$/m)
    assert.match(printed.stdout, new RegExp(`Read the full saved report first: ${reportPath.replaceAll('.', '\\.')}`))
    assert.match(printed.stdout, /### runtime-env-template \(high, fail\)/)
    assert.match(printed.stdout, /docs\/rules\/runtime-env-template\.md/)
    assert.match(printed.stdout, /Never read, write, or print the contents of any value-bearing/)
    assert.match(printed.stdout, /## Definition of done/)
    assert.doesNotMatch(printed.stdout, /## Readiness report \(inlined\)/)
    assert.match(fs.readFileSync(reportPath, 'utf8'), /^# Open Mercato production readiness report/m)
    assert.equal(stub.invocation(), null)

    const inlined = run(['apply', root, '--mode', 'agent', '--print-prompt', '--no-color'])
    assert.equal(inlined.status, 0, inlined.stderr)
    assert.match(inlined.stdout, /## Readiness report \(inlined\)/)
    assert.match(inlined.stdout, /# Open Mercato production readiness report/)

    const dry = run(['apply', root, '--mode', 'agent', '--cezar-run', stub.binary, '--dry-run', '--no-color'])
    assert.equal(dry.status, 0, dry.stderr)
    assert.match(dry.stdout, /would delegate to cezar-run/)
    assert.match(dry.stdout, new RegExp(`command: ${stub.binary.replaceAll('.', '\\.')}`))
    assert.equal(stub.invocation(), null)

    const spawned = run(['apply', root, '--mode', 'agent', '--cezar-run', stub.binary, '--markdown', reportPath, '--yes', '--no-color'])
    assert.equal(spawned.status, 0, spawned.stderr)
    assert.match(spawned.stdout, /stub cezar-run invoked/)
    const invocation = stub.invocation()
    assert.ok(invocation, 'the stub should have been spawned')
    assert.equal(invocation.argv[0], 'run')
    assert.match(invocation.argv[1] ?? '', /^# Task: apply Open Mercato production-readiness remediations/)
    assert.match(invocation.argv[1] ?? '', new RegExp(`Read the full saved report first: ${reportPath.replaceAll('.', '\\.')}`))
    assert.equal(invocation.argv[2], '--repo')
    assert.equal(invocation.argv[3], fs.realpathSync(root))
    assert.equal(invocation.argv.length, 4, 'no model or provider is ever passed')

    const missing = run(['apply', root, '--mode', 'agent', '--cezar-run', path.join(root, 'no-such-binary'), '--yes', '--no-color'])
    assert.equal(missing.status, 2)
    assert.match(missing.stderr, /does not point at an executable file/)
  } finally {
    stub.remove()
    removeFixture(reportDirectory)
    removeFixture(root)
  }
})

test('apply-only flags and scan-only flags stay separate, and scan stays read-only', () => {
  const root = makeAppFixture({ files: brokenFiles(), git: 'commit' })
  try {
    const wrongCommand = run(['scan', root, '--yes'])
    assert.equal(wrongCommand.status, 2)
    assert.match(wrongCommand.stderr, /--yes is only valid for "mercato-readiness apply"/)

    const wrongThreshold = run(['apply', root, '--fail-on', 'high'])
    assert.equal(wrongThreshold.status, 2)
    assert.match(wrongThreshold.stderr, /--fail-on is only valid for "mercato-readiness scan"/)

    const promptWithoutAgent = run(['apply', root, '--print-prompt'])
    assert.equal(promptWithoutAgent.status, 2)
    assert.match(promptWithoutAgent.stderr, /--print-prompt requires --mode agent/)

    const scanned = run([root, '--no-color'])
    assert.equal(scanned.status, 0, scanned.stderr)
    assert.equal(fixtureStatus(root), '', 'scan must not touch the scanned application')
  } finally {
    removeFixture(root)
  }
})
