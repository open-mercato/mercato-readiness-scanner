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
  autofix: AutofixDescriptor
}

/**
 * `safe-additive` fixes are purely additive and cannot destroy data: they create a file that
 * does not exist, append a missing line to an append-only policy file, or insert a missing
 * key. `manual-only` fixes need a human decision, rewrite existing configuration, or touch
 * secret-bearing surfaces, so the apply mode never performs them.
 */
export type AutofixSafety = 'safe-additive' | 'manual-only'

export type AutofixAction =
  /** Create `path` with `contents`; refused when anything already exists at that path. */
  | { kind: 'create-file', path: string, contents: string, description: string }
  /**
   * Append `lines` that are absent from the existing line set; never rewrites a line.
   *
   * Set `force` when the planner has already decided the line is needed even though it appears
   * verbatim earlier in the file — in a last-match-wins format such as `.gitignore`, re-appending
   * a listed-but-overridden pattern is the fix. Idempotence then rests on the planner emitting no
   * action once the file's effective state is correct.
   */
  | { kind: 'append-lines', path: string, lines: string[], description: string, force?: boolean }
  /** Insert a missing `package.json` script key; never changes an existing value. */
  | { kind: 'add-npm-script', name: string, value: string, description: string }

export type AutofixDescriptor =
  | { safety: 'manual-only', reason: string }
  | { safety: 'safe-additive', summary: string, plan: (context: ScanContext) => AutofixAction[] }

/** One failing rule the apply mode can safely act on, with the actions it would perform. */
export type PlannedFix = {
  id: string
  title: string
  severity: Severity
  actions: AutofixAction[]
}

/** One rule the apply mode deliberately leaves to a human, with the reason and its docs page. */
export type SkippedFix = {
  id: string
  title: string
  severity: Severity
  status: FindingStatus
  reason: string
  docsUrl: string
}

export type AppliedChange = {
  id: string
  description: string
  path: string | null
  /** `false` when the target was already in the desired state, which keeps apply idempotent. */
  changed: boolean
  note: string | null
}

export type ApplyPlan = {
  root: string
  planned: PlannedFix[]
  skipped: SkippedFix[]
}

export type ApplyOutcome = {
  plan: ApplyPlan
  changes: AppliedChange[]
  dryRun: boolean
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
