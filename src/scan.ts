import path from 'node:path'
import { createScanContext, findAppRoot } from './app.js'
import { RULES } from './rules.js'
import type { ScanReport, ScanSummary } from './types.js'

export const VERSION = '0.1.0'

export class InvalidTargetError extends Error {
  override name = 'InvalidTargetError'
}

export class InvalidRuleSelectionError extends Error {
  override name = 'InvalidRuleSelectionError'
}

export type ScanOptions = {
  ignoreRules?: readonly string[]
  onlyRules?: readonly string[]
  environment?: Readonly<Record<string, string | undefined>>
}

function displayName(value: string): string {
  // eslint-disable-next-line no-control-regex -- strip control characters from untrusted paths
  return value.replace(/[\u0000-\u001F\u007F]/g, '?').slice(0, 160) || 'open-mercato-app'
}

export function scan(start: string, options?: ScanOptions): ScanReport
export function scan(start: string, now?: Date, options?: ScanOptions): ScanReport
export function scan(start: string, nowOrOptions: Date | ScanOptions = new Date(), explicitOptions: ScanOptions = {}): ScanReport {
  const now = nowOrOptions instanceof Date ? nowOrOptions : new Date()
  const options = nowOrOptions instanceof Date ? explicitOptions : nowOrOptions
  const known = new Set(RULES.map(({ id }) => id))
  const unknown = [...options.ignoreRules ?? [], ...options.onlyRules ?? []].filter((id) => !known.has(id))
  if (unknown.length) throw new InvalidRuleSelectionError(`Unknown rule ID: ${unknown.join(', ')}. Use --list-rules to see available IDs.`)
  const ignored = new Set(options.ignoreRules)
  const only = options.onlyRules === undefined ? null : new Set(options.onlyRules)
  const root = findAppRoot(start)
  if (!root) throw new InvalidTargetError('No create-mercato-app application was found here or in a parent directory.')
  const context = createScanContext(root, options.environment)
  const results = RULES.map(({ check, ...metadata }) => {
    const outcome = ignored.has(metadata.id) || (only !== null && !only.has(metadata.id))
      ? { status: 'skipped' as const, summary: 'Disabled by explicit rule selection.' }
      : check(context)
    return { ...metadata, ...outcome, evidence: outcome.evidence ?? [] }
  })
  const summary: ScanSummary = { total: results.length, pass: 0, fail: 0, warning: 0, skipped: 0 }
  for (const result of results) summary[result.status] += 1
  return {
    schemaVersion: 1,
    tool: { name: '@open-mercato/readiness-scanner', version: VERSION },
    scannedAt: now.toISOString(),
    target: displayName(path.basename(root)),
    summary,
    results,
  }
}
