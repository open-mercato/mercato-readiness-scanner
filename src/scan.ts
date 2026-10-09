import path from 'node:path'
import { createScanContext, findAppRoot } from './app.js'
import { RULES } from './rules.js'
import type { ScanReport, ScanSummary } from './types.js'

export const VERSION = '0.1.0'

export class InvalidTargetError extends Error {
  override name = 'InvalidTargetError'
}

function displayName(value: string): string {
  return value.replace(/[\u0000-\u001F\u007F]/g, '?').slice(0, 160) || 'open-mercato-app'
}

export function scan(start: string, now = new Date()): ScanReport {
  const root = findAppRoot(start)
  if (!root) throw new InvalidTargetError('No create-mercato-app application was found here or in a parent directory.')
  const context = createScanContext(root)
  const results = RULES.map(({ check, ...metadata }) => {
    const outcome = check(context)
    return { ...metadata, ...outcome, evidence: outcome.evidence ?? [] }
  })
  const summary: ScanSummary = { total: results.length, pass: 0, fail: 0, warning: 0, skipped: 0 }
  for (const result of results) summary[result.status] += 1
  return {
    schemaVersion: 1,
    tool: { name: '@open-mercato/mercato-readiness-scanner', version: VERSION },
    scannedAt: now.toISOString(),
    target: displayName(path.basename(root)),
    summary,
    results,
  }
}
