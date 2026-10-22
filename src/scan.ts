import path from 'node:path'
import { createScanContext, findScanTarget } from './app.js'
import { RULES } from './rules.js'
import type { ScanContext, ScanReport, ScanSummary } from './types.js'

export const VERSION = '0.2.1'

export type ScanOptions = { checkSecrets?: boolean }

export class InvalidTargetError extends Error {
  override name = 'InvalidTargetError'
}

function displayName(value: string): string {
  return value.replace(/[\u0000-\u001F\u007F]/g, '?').slice(0, 160) || 'open-mercato-app'
}

export type ResolvedTarget = {
  root: string
  context: ScanContext
}

/** Locates the application and builds its read-only scan context, or throws InvalidTargetError. */
export function resolveTarget(start: string, options: ScanOptions = {}): ResolvedTarget {
  const target = findScanTarget(start)
  if (!target) throw new InvalidTargetError('No create-mercato-app application was found here or in a parent directory.')
  if (target.kind === 'monorepo') {
    throw new InvalidTargetError('[runtime-standalone-application] The Open Mercato monorepo is not a valid way to start a production app. Create a standalone application with create-mercato-app and run the readiness scanner there.')
  }
  const { root } = target
  return { root, context: createScanContext(root, options) }
}

export function scan(start: string, now = new Date(), options: ScanOptions = {}): ScanReport {
  return scanTarget(resolveTarget(start, options), now)
}

export function scanTarget({ root, context }: ResolvedTarget, now = new Date()): ScanReport {
  // `autofix` is dropped here on purpose: it is apply-mode metadata, not part of the
  // versioned report contract in docs/report.schema.json.
  const results = RULES.map(({ check, autofix, ...metadata }) => {
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
