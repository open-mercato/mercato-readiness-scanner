import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { spawnSync } from 'node:child_process'
import { formatMarkdown } from './formatters.js'
import { RULES } from './rules.js'
import type { ApplyPlan, RuleResult, ScanReport } from './types.js'

/** Overrides the `cezar-run` binary without assuming a PATH entry. */
export const CEZAR_RUN_ENV = 'MERCATO_READINESS_CEZAR_RUN'
const DEFAULT_CEZAR_RUN = 'cezar-run'

export class AgentUnavailableError extends Error {
  override name = 'AgentUnavailableError'
}

export type PromptInput = {
  /** Application root being remediated. */
  root: string
  report: ScanReport
  plan: ApplyPlan
  /** Absolute path of a report this run saved, when one exists. */
  reportPath?: string | undefined
}

function describe(result: RuleResult, autofixable: boolean): string[] {
  const lines = [
    `### ${result.id} (${result.severity}, ${result.status})`,
    `- Rule: ${result.title}`,
    `- Finding: ${result.summary}`,
  ]
  for (const evidence of result.evidence) lines.push(`- Evidence: ${evidence}`)
  lines.push(`- Remediation: ${result.remediation}`, `- Docs: ${result.docsUrl}`)
  if (autofixable) lines.push('- Note: `mercato-readiness apply` can add this safely on its own; prefer running that for this rule.')
  return lines
}

/**
 * Builds the remediation prompt handed to `cezar-run`.
 *
 * The prompt references the saved report when this run wrote one and inlines the Markdown report
 * otherwise, so the agent always receives the findings it must act on.
 */
export function buildAgentPrompt(input: PromptInput): string {
  const safeIds = new Set(RULES.filter((rule) => rule.autofix.safety === 'safe-additive').map((rule) => rule.id))
  const failing = input.report.results.filter((result) => result.status === 'fail')
  const review = input.report.results.filter((result) => result.status === 'warning')
  const lines = [
    '# Task: apply Open Mercato production-readiness remediations',
    '',
    `Repository: ${input.root}`,
    `Report produced by: ${input.report.tool.name}@${input.report.tool.version} at ${input.report.scannedAt}`,
    `Summary: ${input.report.summary.fail} failed, ${input.report.summary.warning} need review, ${input.report.summary.pass} passed, ${input.report.summary.skipped} skipped.`,
    '',
  ]
  if (input.reportPath) lines.push('## Readiness report', '', `Read the full saved report first: ${input.reportPath}`, '')
  else lines.push('## Readiness report (inlined)', '', '```markdown', formatMarkdown(input.report).trimEnd(), '```', '')
  lines.push(
    '## Rules to fix',
    '',
    failing.length ? 'Fix every failing rule below. Each rule has a permanent documentation page; read it before changing anything.' : 'No rule is failing. Do not change anything.',
    '',
  )
  for (const result of failing) lines.push(...describe(result, safeIds.has(result.id)), '')
  if (review.length) {
    lines.push(
      '## Rules that need operator verification (do not fabricate evidence)',
      '',
      'A static scan cannot prove these. Do not mark them resolved and do not invent certificate, backup, or alerting evidence. Report what an operator still has to verify.',
      '',
    )
    for (const result of review) lines.push(`- ${result.id} (${result.severity}): ${result.summary}`)
    lines.push('')
  }
  lines.push(
    '## Constraints',
    '',
    '- Never read, write, or print the contents of any value-bearing `.env*` file, private key, or credential store.',
    '- Never commit secrets, and never put a real secret value in a tracked file.',
    '- Do not delete or truncate existing files; make the smallest additive change that satisfies the rule.',
    '- Do not weaken, delete, or skip existing tests or CI steps to make a rule pass.',
    '- Never execute the target application scripts or load application code. List validation commands for the operator to run separately.',
    '',
    '## Definition of done',
    '',
    `- \`${input.report.tool.name}\` reports no failing rule for the fixes you made, re-verified by re-running the scanner.`,
    '- Every change is committed with a clear message explaining which rule id it addresses.',
    '- Anything you could not fix is reported back with the rule id and the reason.',
    '',
  )
  if (input.plan.planned.length) {
    lines.push(
      '## Already handled by the scanner itself',
      '',
      `\`mercato-readiness apply\` can write these without an agent: ${input.plan.planned.map((fix) => fix.id).join(', ')}.`,
      '',
    )
  }
  return lines.join('\n')
}

export type AgentBinary = {
  command: string
  source: 'flag' | 'env' | 'path'
}

/**
 * Resolves the `cezar-run` binary from an explicit flag, then the override environment variable,
 * then a bare `cezar-run` on PATH. An explicit flag or env value must point at an executable file.
 */
export function resolveAgentBinary(override?: string, environment: NodeJS.ProcessEnv = process.env): AgentBinary {
  const explicit = override ?? environment[CEZAR_RUN_ENV]
  const source = override ? 'flag' : 'env'
  if (!explicit) return { command: DEFAULT_CEZAR_RUN, source: 'path' }
  const resolved = path.resolve(explicit)
  try {
    fs.accessSync(resolved, fs.constants.X_OK)
    if (!fs.statSync(resolved).isFile()) throw new Error('not a file')
  } catch {
    const origin = source === 'flag' ? '--cezar-run' : CEZAR_RUN_ENV
    throw new AgentUnavailableError(`${origin} does not point at an executable file: ${explicit}`)
  }
  return { command: resolved, source }
}

export type AgentInvocation = {
  command: string
  args: string[]
}

/** `cezar-run run "<prompt>" --repo <root>`; the provider and model stay cezar-run's decision. */
export function agentInvocation(binary: AgentBinary, prompt: string, root: string, workflow?: string): AgentInvocation {
  return { command: binary.command, args: ['run', prompt, '--repo', root, ...(workflow ? ['--workflow', workflow] : [])] }
}

export function spawnAgent(invocation: AgentInvocation, timeoutMs = 15 * 60_000): number {
  const result = spawnSync(invocation.command, invocation.args, { stdio: 'inherit', timeout: timeoutMs })
  if (result.error) {
    const code = (result.error as NodeJS.ErrnoException).code
    if (code === 'ETIMEDOUT') throw new AgentUnavailableError('cezar-run exceeded the execution timeout; inspect the target working tree for partial changes.')
    if (code === 'ENOENT') throw new AgentUnavailableError(`cezar-run was not found as "${invocation.command}". Install it, or point --cezar-run / ${CEZAR_RUN_ENV} at the binary.`)
    throw result.error
  }
  return result.status ?? 3
}
