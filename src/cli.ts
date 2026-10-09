#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import readline from 'node:readline/promises'
import { agentInvocation, AgentUnavailableError, buildAgentPrompt, CEZAR_RUN_ENV, resolveAgentBinary, spawnAgent } from './agent.js'
import { applyPlan, ApplyRefusedError, planApply } from './apply.js'
import { formatApplyOutcome, formatApplyPlan, formatJson, formatMarkdown, formatTerminal } from './formatters.js'
import { gitWorktreeState } from './git.js'
import { InvalidTargetError, resolveTarget, scan, scanTarget, VERSION } from './scan.js'
import type { ApplyPlan, ScanReport, Severity } from './types.js'

type Format = 'terminal' | 'markdown' | 'json'
type Command = 'scan' | 'apply'
type ApplyMode = 'direct' | 'agent'
type Options = {
  command: Command
  start: string
  format: Format
  formatExplicit: boolean
  output?: string
  markdown?: string
  json?: string
  color: boolean
  failOn: Severity | 'never'
  mode: ApplyMode
  assumeYes: boolean
  allowDirty: boolean
  dryRun: boolean
  printPrompt: boolean
  cezarRun?: string
  workflow?: string
}

class CliUsageError extends Error {
  override name = 'CliUsageError'
}

/** A refused hard precondition of `apply`: not a git worktree, dirty worktree, or no consent. */
class PreconditionError extends Error {
  override name = 'PreconditionError'
}

const HELP = `Open Mercato production-readiness scanner

Usage:
  mercato-readiness scan [path] [options]
  mercato-readiness apply [path] [options]
  mercato-readiness [path] [options]

Options:
  --format <terminal|markdown|json>  stdout format (default: terminal)
  --output <path|->                 save the selected format; .md/.json infers format
                                    a file suppresses stdout; - writes to stdout
  --markdown <path>                 additionally save a Markdown report
  --json <path>                     additionally save a JSON report
  --fail-on <critical|high|medium|low|never>
                                    scan only: return exit 1 when a failed rule meets
                                    the threshold (default: never)
  --no-color                        disable ANSI colors
  --help                            show help
  --version                         show version

Apply options (apply only; scan never writes to the scanned application):
  --mode <direct|agent>             direct: this CLI writes the safe, purely additive
                                    fixes itself (default)
                                    agent: hand a prepared remediation prompt to the
                                    cezar-run AI coding agent instead
  --yes, --non-interactive          skip the confirmation question; required when stdin
                                    is not a TTY
  --allow-dirty                     allow a target worktree with uncommitted changes
  --dry-run                         show what would happen; write and spawn nothing
  --print-prompt                    agent mode: print the prompt and exit
  --cezar-run <path>                path to the cezar-run binary
                                    (env: ${CEZAR_RUN_ENV})
  --workflow <name>                 agent mode: cezar-run workflow to use

Apply writes only purely additive fixes, never overwrites or truncates existing content,
never touches .env* or credential files, and never runs the target's scripts. The target
must be a git working tree, because git is the only undo for those writes.

Examples:
  mercato-readiness scan .
  mercato-readiness scan . --markdown readiness.md --json readiness.json
  mercato-readiness scan . --format json --output readiness.json --fail-on high
  mercato-readiness apply . --dry-run
  mercato-readiness apply . --yes
  mercato-readiness apply . --mode agent --markdown readiness.md --print-prompt
`

const APPLY_ONLY_FLAGS = ['--mode', '--yes', '--non-interactive', '--allow-dirty', '--dry-run', '--print-prompt', '--cezar-run', '--workflow'] as const

function takeValue(args: string[], index: number, flag: string, allowDash = false): string {
  const value = args[index + 1]
  if (!value || (value.startsWith('-') && !(allowDash && value === '-'))) throw new CliUsageError(`${flag} requires a value.`)
  args.splice(index, 2)
  return value
}

function parseArgs(argv: string[]): Options | 'help' | 'version' {
  const args = [...argv]
  let command: Command = 'scan'
  if (args[0] === 'scan') args.shift()
  else if (args[0] === 'apply') {
    args.shift()
    command = 'apply'
  }
  if (args.includes('--help') || args.includes('-h')) return 'help'
  if (args.includes('--version') || args.includes('-v')) return 'version'
  const options: Options = {
    command, start: '.', format: 'terminal', formatExplicit: false, color: process.stdout.isTTY, failOn: 'never',
    mode: 'direct', assumeYes: false, allowDirty: false, dryRun: false, printPrompt: false,
  }
  const applyOnly = (token: string): void => {
    if (command !== 'apply') throw new CliUsageError(`${token} is only valid for "mercato-readiness apply".`)
  }
  for (let index = 0; index < args.length;) {
    const token = args[index]
    if (token === '--no-color') { options.color = false; args.splice(index, 1); continue }
    if (token === '--format') {
      const value = takeValue(args, index, token)
      if (!['terminal', 'markdown', 'json'].includes(value)) throw new CliUsageError(`Unsupported format: ${value}`)
      options.format = value as Format
      options.formatExplicit = true
      continue
    }
    if (token === '--output') { options.output = takeValue(args, index, token, true); continue }
    if (token === '--markdown') { options.markdown = takeValue(args, index, token); continue }
    if (token === '--json') { options.json = takeValue(args, index, token); continue }
    if (token === '--fail-on') {
      if (command === 'apply') throw new CliUsageError('--fail-on is only valid for "mercato-readiness scan"; apply reports its own exit codes.')
      const value = takeValue(args, index, token)
      if (!['critical', 'high', 'medium', 'low', 'never'].includes(value)) throw new CliUsageError(`Unsupported fail threshold: ${value}`)
      options.failOn = value as Severity | 'never'
      continue
    }
    if (token === '--mode') {
      applyOnly(token)
      const value = takeValue(args, index, token)
      if (!['direct', 'agent'].includes(value)) throw new CliUsageError(`Unsupported apply mode: ${value}`)
      options.mode = value as ApplyMode
      continue
    }
    if (token === '--yes' || token === '--non-interactive') { applyOnly(token); options.assumeYes = true; args.splice(index, 1); continue }
    if (token === '--allow-dirty') { applyOnly(token); options.allowDirty = true; args.splice(index, 1); continue }
    if (token === '--dry-run') { applyOnly(token); options.dryRun = true; args.splice(index, 1); continue }
    if (token === '--print-prompt') { applyOnly(token); options.printPrompt = true; args.splice(index, 1); continue }
    if (token === '--cezar-run') { applyOnly(token); options.cezarRun = takeValue(args, index, token); continue }
    if (token === '--workflow') { applyOnly(token); options.workflow = takeValue(args, index, token); continue }
    if (token?.startsWith('-')) throw new CliUsageError(`Unknown option: ${token}`)
    index += 1
  }
  if (args.length > 1) throw new CliUsageError('Pass at most one application path.')
  if (args[0]) options.start = args[0]
  if (options.output && !options.formatExplicit) {
    if (options.output.endsWith('.md')) options.format = 'markdown'
    if (options.output.endsWith('.json')) options.format = 'json'
  }
  if (options.printPrompt && options.mode !== 'agent') throw new CliUsageError('--print-prompt requires --mode agent.')
  return options
}

function render(report: ScanReport, format: Format, color: boolean): string {
  if (format === 'json') return formatJson(report)
  if (format === 'markdown') return formatMarkdown(report)
  return formatTerminal(report, color)
}

function writeReport(destination: string, contents: string): string {
  const absolute = path.resolve(destination)
  fs.mkdirSync(path.dirname(absolute), { recursive: true })
  const temporary = `${absolute}.tmp-${process.pid}`
  fs.writeFileSync(temporary, contents, { encoding: 'utf8', mode: 0o600 })
  fs.renameSync(temporary, absolute)
  return absolute
}

function shouldFail(report: ScanReport, threshold: Severity | 'never'): boolean {
  if (threshold === 'never') return false
  const rank: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 }
  return report.results.some((result) => result.status === 'fail' && rank[result.severity] >= rank[threshold])
}

function out(contents: string): void {
  fs.writeSync(process.stdout.fd, contents)
}

function interactive(): boolean {
  return process.stdin.isTTY === true && process.stdout.isTTY === true
}

/**
 * Asks for consent. Never prompts on a non-TTY: without `--yes` that is a usage error, so a CI
 * job fails fast instead of hanging on a question nobody can answer.
 */
async function confirm(question: string, options: Options): Promise<void> {
  if (options.assumeYes) return
  if (!interactive()) {
    throw new CliUsageError('Refusing to prompt because stdin or stdout is not a TTY. Pass --yes (or --non-interactive) to apply without a confirmation question.')
  }
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  try {
    const answer = await rl.question(`${question} [y/N] `)
    if (!/^(?:y|yes)$/i.test(answer.trim())) throw new PreconditionError('Aborted: nothing was changed.')
  } finally {
    rl.close()
  }
}

function runScan(options: Options): number {
  const report = scan(options.start)
  const stdout = render(report, options.format, options.color)
  if (!options.output || options.output === '-') out(stdout)
  else writeReport(options.output, stdout)
  if (options.markdown) writeReport(options.markdown, formatMarkdown(report))
  if (options.json) writeReport(options.json, formatJson(report))
  return shouldFail(report, options.failOn) ? 1 : 0
}

/** Enforces the hard precondition: an apply needs a git working tree the user can revert. */
function requireRevertableWorktree(root: string, allowDirty: boolean): void {
  const state = gitWorktreeState(root)
  if (!state.insideWorktree) {
    throw new PreconditionError(`${root} is not a git working tree. Run "git init" and commit a baseline first: git is the only undo for the files apply writes.`)
  }
  if (allowDirty) return
  if (state.pending === null) {
    throw new PreconditionError('git status could not be read for the target, so uncommitted work cannot be ruled out. Re-run with --allow-dirty to apply anyway.')
  }
  if (state.pending.length) {
    const shown = state.pending.slice(0, 10).map((entry) => `  ${entry}`)
    const extra = state.pending.length > 10 ? [`  … ${state.pending.length - 10} more`] : []
    throw new PreconditionError([
      'The target worktree has uncommitted changes, so the files apply writes could not be told apart from yours.',
      ...shown,
      ...extra,
      'Commit or stash them, or re-run with --allow-dirty.',
    ].join('\n'))
  }
}

/** Saves the requested reports and returns the path worth handing to an agent, if any. */
function saveReports(report: ScanReport, options: Options): string | undefined {
  const saved: string[] = []
  if (options.output && options.output !== '-') saved.push(writeReport(options.output, render(report, options.format, false)))
  if (options.markdown) saved.unshift(writeReport(options.markdown, formatMarkdown(report)))
  if (options.json) saved.push(writeReport(options.json, formatJson(report)))
  return saved[0]
}

async function runApply(options: Options): Promise<number> {
  const target = resolveTarget(options.start)
  if (!options.printPrompt) requireRevertableWorktree(target.root, options.allowDirty)
  const report = scanTarget(target)
  const reportPath = saveReports(report, options)
  const plan = planApply(target, report)
  if (options.mode === 'agent') return runAgentApply(options, target.root, report, plan, reportPath)
  if (options.dryRun) {
    out(formatApplyOutcome(applyPlan(plan, true), options.color))
    return 0
  }
  if (!plan.planned.length) {
    out(formatApplyOutcome({ plan, changes: [], dryRun: false }, options.color))
    return 0
  }
  // The preview only earns its space when a question follows it; --yes output stays terse.
  if (!options.assumeYes) out(formatApplyPlan(plan, options.color))
  await confirm(`Write ${plan.planned.reduce((total, fix) => total + fix.actions.length, 0)} additive change(s) to ${target.root}?`, options)
  out(formatApplyOutcome(applyPlan(plan, false), options.color))
  return 0
}

async function runAgentApply(options: Options, root: string, report: ScanReport, plan: ApplyPlan, reportPath: string | undefined): Promise<number> {
  const prompt = buildAgentPrompt({ root, report, plan, reportPath })
  if (options.printPrompt) {
    out(prompt.endsWith('\n') ? prompt : `${prompt}\n`)
    return 0
  }
  const invocation = agentInvocation(resolveAgentBinary(options.cezarRun), prompt, root, options.workflow)
  if (options.dryRun) {
    out(`Dry run: would delegate to cezar-run and write nothing itself.\n  command: ${invocation.command}\n  args: ${invocation.args.map((value, index) => index === 1 ? `<prompt, ${prompt.length} chars>` : value).join(' ')}\n  report: ${reportPath ?? 'inlined in the prompt'}\nUse --print-prompt to inspect the prompt.\n`)
    return 0
  }
  await confirm(`Delegate remediation of ${report.summary.fail} failing rule(s) in ${root} to ${invocation.command}?`, options)
  return spawnAgent(invocation)
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  try {
    const parsed = parseArgs(argv)
    if (parsed === 'help') { out(HELP); return 0 }
    if (parsed === 'version') { out(`${VERSION}\n`); return 0 }
    return parsed.command === 'apply' ? await runApply(parsed) : runScan(parsed)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    try {
      fs.writeSync(process.stderr.fd, `mercato-readiness: ${message}\n`)
      if (error instanceof ApplyRefusedError) fs.writeSync(process.stderr.fd, 'mercato-readiness: review the working tree with "git status"; earlier safe writes may already be on disk.\n')
    } catch {
    }
    const usage = error instanceof CliUsageError || error instanceof InvalidTargetError
      || error instanceof PreconditionError || error instanceof AgentUnavailableError || error instanceof ApplyRefusedError
    return usage ? 2 : 3
  }
}

process.exitCode = await main()
