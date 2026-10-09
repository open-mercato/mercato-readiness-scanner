export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type FindingStatus = 'pass' | 'fail' | 'warning' | 'skipped'

export type RuleCheck = {
  status: FindingStatus
  summary: string
  evidence?: string[]
}

export type RuleResult = {
  id: string
  title: string
  category: string
  severity: Severity
  status: FindingStatus
  summary: string
  evidence: string[]
  remediation: string
  docsUrl: string
}

export type ScanSummary = Record<FindingStatus, number> & {
  total: number
}

export type ScanReport = {
  schemaVersion: 1
  tool: {
    name: '@open-mercato/mercato-readiness-scanner'
    version: string
  }
  scannedAt: string
  target: string
  summary: ScanSummary
  results: RuleResult[]
}

export type RuleDefinition = Omit<RuleResult, 'status' | 'summary' | 'evidence'> & {
  check: (context: ScanContext) => RuleCheck
}

export type ScanContext = {
  root: string
  packageJson: Record<string, unknown>
  trackedFiles: ReadonlySet<string> | null
  exists: (relativePath: string) => boolean
  readText: (relativePath: string) => string | null
  collectDeploymentText: () => string
  collectOperationalDocs: () => string
  collectCiText: () => string
  collectCiWorkflows: () => ReadonlyArray<{ path: string, source: string }>
}
