import assert from 'node:assert/strict'
import fs from 'node:fs'
import { Ajv2020 } from 'ajv/dist/2020.js'
import { fullFormats } from 'ajv-formats/dist/formats.js'
import { RULES } from '../src/rules.js'
import type { ScanReport } from '../src/types.js'

const schema: unknown = JSON.parse(fs.readFileSync(new URL('../docs/report.schema.json', import.meta.url), 'utf8'))
const ajv = new Ajv2020({ allErrors: true, formats: fullFormats })
const validate = ajv.compile<ScanReport>(schema as object)

export function assertReport(value: unknown): asserts value is ScanReport {
  assert.equal(validate(value), true, JSON.stringify(validate.errors))
  const report = value as ScanReport
  assert.deepEqual(report.results.map(({ id }) => id), RULES.map(({ id }) => id))
  for (const status of ['pass', 'fail', 'warning', 'skipped'] as const) {
    assert.equal(report.summary[status], report.results.filter((result) => result.status === status).length)
  }
  assert.equal(report.summary.total, report.results.length)
}
