#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { formatJson, formatMarkdown, formatTerminal } from './formatters.js'
import { scan, VERSION } from './scan.js'
import type { ScanReport, Severity } from './types.js'

type Format = 'terminal' | 'markdown' | 'json'
type Options = {
  start: string
  format: Format
  formatExplicit: boolean
  output?: string
  markdown?: string
  json?: string
  color: boolean
  failOn: Severity | 'never'
}

const HELP = `Open Mercato production-readiness scanner

Usage:
  mercato-readiness scan [path] [options]
  mercato-readiness [path] [options]

Options:
  --format <terminal|markdown|json>  stdout format (default: terminal)
  --output <path>                   save the selected format; .md/.json infers format
  --markdown <path>                 additionally save a Markdown report
  --json <path>                     additionally save a JSON report
  --fail-on <critical|high|medium|low|never>
                                    return exit 1 when a failed rule meets the threshold
                                    (default: never)
  --no-color                        disable ANSI colors
  --help                            show help
  --version                         show version

Examples:
  mercato-readiness scan .
  mercato-readiness scan . --markdown readiness.md --json readiness.json
  mercato-readiness scan . --format json --output readiness.json --fail-on high
`

function takeValue(args: string[], index: number, flag: string): string {
  const value = args[index + 1]
  if (!value || value.startsWith('-')) throw new Error(`${flag} requires a value.`)
  args.splice(index, 2)
  return value
}

function parseArgs(argv: string[]): Options | 'help' | 'version' {
  const args = [...argv]
  if (args[0] === 'scan') args.shift()
  if (args.includes('--help') || args.includes('-h')) return 'help'
  if (args.includes('--version') || args.includes('-v')) return 'version'
  const options: Options = { start: '.', format: 'terminal', formatExplicit: false, color: process.stdout.isTTY, failOn: 'never' }
  for (let index = 0; index < args.length;) {
    const token = args[index]
    if (token === '--no-color') { options.color = false; args.splice(index, 1); continue }
    if (token === '--format') {
      const value = takeValue(args, index, token)
      if (!['terminal', 'markdown', 'json'].includes(value)) throw new Error(`Unsupported format: ${value}`)
      options.format = value as Format
      options.formatExplicit = true
      continue
    }
    if (token === '--output') { options.output = takeValue(args, index, token); continue }
    if (token === '--markdown') { options.markdown = takeValue(args, index, token); continue }
    if (token === '--json') { options.json = takeValue(args, index, token); continue }
    if (token === '--fail-on') {
      const value = takeValue(args, index, token)
      if (!['critical', 'high', 'medium', 'low', 'never'].includes(value)) throw new Error(`Unsupported fail threshold: ${value}`)
      options.failOn = value as Severity | 'never'
      continue
    }
    if (token?.startsWith('-')) throw new Error(`Unknown option: ${token}`)
    index += 1
  }
  if (args.length > 1) throw new Error('Pass at most one application path.')
  if (args[0]) options.start = args[0]
  if (options.output && !options.formatExplicit) {
    if (options.output.endsWith('.md')) options.format = 'markdown'
    if (options.output.endsWith('.json')) options.format = 'json'
  }
  return options
}

function render(report: ScanReport, format: Format, color: boolean): string {
  if (format === 'json') return formatJson(report)
  if (format === 'markdown') return formatMarkdown(report)
  return formatTerminal(report, color)
}

function writeReport(destination: string, contents: string): void {
  const absolute = path.resolve(destination)
  fs.mkdirSync(path.dirname(absolute), { recursive: true })
  const temporary = `${absolute}.tmp-${process.pid}`
  fs.writeFileSync(temporary, contents, { encoding: 'utf8', mode: 0o600 })
  fs.renameSync(temporary, absolute)
}

function shouldFail(report: ScanReport, threshold: Severity | 'never'): boolean {
  if (threshold === 'never') return false
  const rank: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 }
  return report.results.some((result) => result.status === 'fail' && rank[result.severity] >= rank[threshold])
}

export function main(argv = process.argv.slice(2)): number {
  try {
    const parsed = parseArgs(argv)
    if (parsed === 'help') { process.stdout.write(HELP); return 0 }
    if (parsed === 'version') { process.stdout.write(`${VERSION}\n`); return 0 }
    const report = scan(parsed.start)
    const stdout = render(report, parsed.format, parsed.color)
    process.stdout.write(stdout)
    if (parsed.output) writeReport(parsed.output, stdout)
    if (parsed.markdown) writeReport(parsed.markdown, formatMarkdown(report))
    if (parsed.json) writeReport(parsed.json, formatJson(report))
    return shouldFail(report, parsed.failOn) ? 1 : 0
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    process.stderr.write(`mercato-readiness: ${message}\n`)
    return 2
  }
}

process.exitCode = main()
