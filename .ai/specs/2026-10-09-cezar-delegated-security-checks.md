# Deep security checks delegated to a `cezar-run` agent task

## TLDR

The scanner's 26 rules are deterministic pattern checks over bounded configuration
and documentation surfaces. A whole class of security questions — does this API
route actually enforce authorization, is every tenant-scoped query filtered, does
request input reach a shell or `fetch` sink — needs cross-file semantic reasoning
that a regex engine cannot do honestly. This spec adds an **opt-in deep-security
mode** that delegates exactly those judgement-level checks to an AI agent task
started through the already-installed `cezar-run` CLI, using a *specially prepared*
workflow + skill + test pack that this repository ships and version-controls. The
agent's output is validated against a strict contract and folded into the report as
a separate, explicitly non-deterministic `deepScan` section — the deterministic core
report, its exit codes, and its default output stay byte-for-byte unchanged.

## Resolved assumptions (autonomous defaults)

This spec was written by `om-auto-write-spec` in autonomous mode. The open questions
below were resolved with conservative, reversible defaults. Two carry
`⚠ NEEDS HUMAN CONFIRMATION` because they change the tool's documented safety
posture, and the spec PR stays a draft until they are confirmed.

| # | Question | Applied default | Why | Confirm? |
|---|---|---|---|---|
| Q1 | One spec, or split "CLI delegation plumbing" from "the security-check content pack"? | One spec, four phases. | The pack is the payload of the plumbing and the plumbing is useless without a pack; splitting would produce two specs that only make sense read together. Phase 1 is still independently shippable. | ok |
| Q2 | Do agentic findings merge into `results[]`, or live in their own section? | Own top-level optional `deepScan` section; **not** merged into `results[]`, **not** counted in the top-level `summary`. `schemaVersion` stays `1` (purely additive). | `AGENTS.md` requires deterministic findings and a preserved schema version. A consumer that ignores `deepScan` sees today's report exactly. | ok |
| Q3 | Does the scanner itself spawn the agent, or only prepare the task and ingest a result produced out-of-band? | Both, phased and gated: `prepare` and `ingest` ship in Phase 1 and never execute an agent; `run` ships in Phase 3 and requires a second explicit `--allow-agent-execution` flag. | `AGENTS.md` says "Ask before … executing code from a scanned application" and "Never execute target application scripts". Spawning an LLM agent with shell access in a target checkout is a real change of posture, so it is opt-in, late, and double-gated. | ⚠ NEEDS HUMAN CONFIRMATION — approving this spec also means amending `AGENTS.md` (Phase 4, step 16). |
| Q4 | What isolates the agent from the operator's checkout? | `cezar-run` already runs every task in its own per-task git worktree; the scanner requires the target to be a git repository with a clean tree and refuses `run` otherwise. | Reuses the existing containment boundary instead of inventing a second one. A non-git target has no isolation, so refusing is the only safe answer. | ok |
| Q5 | Do deep findings affect CI exit codes? | No. `--fail-on` keeps applying to deterministic results only; a separate `--fail-on-deep` (default `never`) is the opt-in gate. | LLM findings are non-deterministic; folding them into the existing gate would make the same commit go red one day and green the next. | ok |
| Q6 | What are "the tests" in the prepared task — static assertions over the target's source, or live probes against a running app? | Static only. The pack's tests are this repository's own zero-dependency Node tests, run in the agent's worktree, reading the target's **source**. Booting the target app, HTTP probing, and any network request are out of scope. | Keeps "Never execute target application scripts" and "Ask before adding active network probes" intact. Live probing is a strictly larger trust decision and deserves its own spec. | ⚠ NEEDS HUMAN CONFIRMATION — if live probing was the intent, Phase 2 changes substantially. |
| Q7 | Which agent runner and model? | Inherit whatever `cezar-run` is configured to use; expose a `--deep-model` passthrough only. | The operator already chose a runner when they installed cezar; the scanner has no business overriding it. | ok |
| Q8 | Is there a cost cap? | No invented budget. A wall-clock `--deep-timeout` (default 900 s) is the only bound, and the run prints the token/cost usage cezar reports. | Inventing a dollar figure would park runs mid-work; a visible cost plus a timeout is honest and reversible. | ok |

## Problem Statement

The scanner recognizes an Open Mercato app and evaluates 26 rules over `package.json`,
`.gitignore`, `.env.example`, deployment manifests, CI configuration, and runbook
documentation. Every rule is a deterministic read of a bounded surface, which is
precisely why its output is trustworthy and why `--fail-on high` is safe in CI.

That design also draws a hard ceiling. The following questions are the ones an
operator most wants answered before a production launch, and none of them is
answerable from configuration text:

- Does every non-public API route enforce an authorization check **before** it
  touches data? The answer lives in the body of each `route.ts`, in whichever
  helper it delegates to, and in what that helper does on the unauthenticated path.
- Is every query in a tenant-scoped module filtered by the tenant key? One missing
  `where` clause is a cross-tenant data leak, and it looks like ordinary code.
- Does request-derived input reach a shell, SQL template, filesystem path, or
  outbound `fetch` without validation? This is a multi-hop dataflow question.
- For each advisory in the lockfile, is the vulnerable code path actually reachable
  from this app? A version comparison answers "vulnerable dependency present";
  it does not answer "exploitable".
- Does the app's own test suite assert the **negative** authorization cases, or only
  the happy paths?

Three things make these a bad fit for `src/rules.ts`. They need semantic reasoning
across many files, so a pattern match either misses real defects or floods the
report with false positives — and a scanner whose `❌` markers are unreliable is
worse than one with fewer checks. They need project-specific judgement about Open
Mercato conventions (the module registry, tenant scoping helpers, the config layer),
which no generic tool encodes. And encoding them would grow a 880-line deterministic
rule engine into a half-maintained mini-SAST.

Meanwhile the environment already contains the right tool. `cezar-run` is installed,
logged in against the operator's own agent subscription, runs each task in an
isolated git worktree, supports a declarative YAML workflow with agent steps, shell
**check** steps and bounded `onFail` retry loops, loads Markdown skills as the
agent's system prompt, and has a headless mode (`cezar run "<task>" --repo <dir>
--workflow <name>`) that needs no cockpit. What is missing is the contract: a
prepared task the scanner ships, and a validated path for its findings back into
the report.

## Proposed Solution

Add a deep-security mode to the CLI with four values, default `off`:

| Mode | What it does | Executes an agent? |
|---|---|---|
| `off` | Nothing. Today's behavior, byte-identical. | no |
| `prepare` | Materializes the shipped agent pack into the target's `.ai/cezar/` and prints the exact `cezar-run` command to run. | no |
| `ingest` | Reads an existing `deep-findings.json`, validates it, renders it in the report. | no |
| `run` | `prepare`, then spawn `cezar-run`, then `ingest`. Requires `--allow-agent-execution`. | yes |

The prepared task is a three-file pack that this repository owns, versions, and
tests in its own CI: a cezar **workflow** (agent step + a check step that runs the
assertion tests, with a bounded retry back to the agent), a cezar **skill** (the
check catalog, the evidence rules, and the hard prohibitions as the agent's system
prompt), and the **tests** (zero-dependency Node tests: contract tests over the
findings file, plus static assertion tests over the target's source that back each
finding with mechanically-checkable evidence).

The agent's only output channel is a single JSON file with a strict schema. The
scanner validates it, maps each finding onto an id in a **shipped catalog** —
findings naming anything else are dropped — sanitizes every evidence string, and
renders the result in a separate, clearly captioned section that carries
`deterministic: false` and a per-finding `confidence`.

### Alternatives considered

1. **More `rules.ts` rules.** Rejected: the target questions need cross-file
   semantic reasoning. A pattern approximation would either miss real defects or
   emit false positives, which destroys the deterministic report's credibility —
   the scanner's single most valuable property.
2. **Vendor a third-party SAST (Semgrep, CodeQL).** Rejected for now: adds a runtime
   dependency and a rule-maintenance burden (`AGENTS.md` requires asking first), and
   a generic engine knows nothing about Open Mercato's tenant scoping, module
   registry, or config layer. Not mutually exclusive with this spec — a future spec
   could add a SAST as another evidence source for the same `deepScan` section.
3. **Call an LLM API directly from the scanner.** Rejected: needs an API key, needs
   network egress from a tool that performs no network calls today, and would
   re-implement worktree isolation, event logging, retries, and cost accounting that
   `cezar-run` already provides against the operator's existing subscription.
4. **Stay fully external — document a command, ingest nothing.** Partially adopted:
   this is exactly `prepare` + `ingest`, and it is Phase 1. Rejected as the *whole*
   answer because without ingestion there is no single report, no schema, no
   sanitization backstop, and no CI story.

## Architecture

The deterministic core is not touched. `src/scan.ts` and `src/rules.ts` keep their
current signatures and behavior; everything new lives behind a new module boundary
and is reachable only from `src/cli.ts` when a deep mode is requested.

```
src/cli.ts            parses the deep flags; orchestrates; renders deterministic
                      report FIRST, then the deep phase
src/scan.ts           UNCHANGED — deterministic ScanReport
src/rules.ts          UNCHANGED — the 26 static rules
src/deep/catalog.ts   the shipped deep-rule catalog (id → title, category,
                      severity, remediation, docsUrl)
src/deep/schema.ts    hand-rolled validator for deep-findings.json (no new dep)
src/deep/sanitize.ts  evidence redaction — the trust backstop
src/deep/ingest.ts    findings file → DeepScanSection
src/deep/pack.ts      materializes assets/deep-pack/ into the target (idempotent)
src/deep/invoke.ts    spawns cezar-run (Phase 3)
src/formatters.ts     renders the deep section in terminal / markdown / json
assets/deep-pack/     the specially prepared task (shipped, versioned, CI-tested)
```

### What changes vs. what is reused

Reused unchanged: `findAppRoot` and `createScanContext` from `src/app.ts` for target
resolution; the `rule()`/`docsUrl` convention from `src/rules.ts` for the deep
catalog; the `writeReport` atomic-write helper in `src/cli.ts`; the existing
`FindingStatus` and `Severity` unions; the three formatter entry points; cezar's own
worktree isolation, retry loop, event log, and cost accounting.

New: the deep catalog, the findings contract and its validator, the sanitizer, the
pack materializer, the invoker, and one optional field on `ScanReport`.

### Data flow (`run` mode)

1. Resolve the target root with the existing `findAppRoot`. Invalid target → exit 2,
   unchanged.
2. Run the deterministic scan and **render and save it first**. A failed or slow
   agent must never cost the operator their static report.
3. Preflight: the target is a git repository; its worktree is clean (override:
   `--deep-allow-dirty`); `cezar-run` resolves on `PATH`; `--allow-agent-execution`
   was passed. Any failure → exit 2 with the specific reason and a pointer to
   `prepare`.
4. Materialize the pack into `<target>/.ai/cezar/`, idempotently. Every generated
   file carries a `generated by mercato-readiness-scanner <version>` header; a file
   whose header is missing or altered is treated as hand-edited, left alone, and
   reported as `skipped`.
5. Spawn `cezar-run run "<task text>" --repo <target> --workflow mercato-security-audit
   [--model <m>]` — no shell, argument array only, `cwd` = target, child stdio
   inherited so the operator watches the live agent log, environment reduced to an
   allowlist (`PATH`, `HOME`, and `CEZ_*` passthrough), killed at `--deep-timeout`.
6. The workflow's final step is a **check step** that runs the pack's tests, so a
   malformed finding set is caught by cezar's own `onFail: {retry: audit, max: 2}`
   loop before the scanner ever reads the file.
7. Read `<target>/.ai/cezar/mercato-security/deep-findings.json`, validate, sanitize,
   map onto the catalog, and render the `deepScan` section.

The agent runs headless, so — per cezar's documented behavior — it cannot dispatch
child tasks: there is no cockpit for `cez task create` to reach. One agent, one
worktree, one findings file.

### The specially prepared task (`assets/deep-pack/`)

```
assets/deep-pack/
  workflows/mercato-security-audit.yaml
  skills/mercato-security-audit.md
  mercato-security/run-tests.mjs
  mercato-security/tests/contract.test.mjs
  mercato-security/tests/<deep-rule-id>.test.mjs   (one per catalog entry)
```

**The workflow** — two steps, so a bad finding set is retried by cezar rather than
surfaced to the operator:

```yaml
name: mercato-security-audit
description: Judgement-level security audit of an Open Mercato app; writes deep-findings.json.
steps:
  - id: audit
    name: Audit
    prompt: "{{task}}"
    skill: mercato-security-audit
    allowedTools: [Read, Grep, Glob, Bash]
  - id: assert
    name: Assert findings
    command: "node .ai/cezar/mercato-security/run-tests.mjs"
    onFail:
      retry: audit
      max: 2
```

`allowedTools` deliberately omits `Edit` and `Write`; the agent produces the findings
file through `Bash`, which the skill constrains to the pack directory. Per cezar's
documentation `Bash` is not allowlist-sandboxed by default, so the real enforcement
is the skill's stated boundary plus the scanner's ingest validator — the latter is
what the design actually relies on.

**The skill** is the agent's system prompt and states, at minimum: the check catalog
with one section per deep rule id and what evidence each requires; the output
contract (path, schema, one finding per catalog id, `skipped` when the surface is
absent); the evidence rules (repo-relative paths with line numbers, never a secret
value, never an absolute or home path, ≤ 240 characters); and the prohibitions —
never run the target's scripts, never start the app, never make a network request,
never read a value-bearing `.env*`, never write outside
`.ai/cezar/mercato-security/`.

**The tests** are two kinds, both this repository's own zero-dependency Node tests:

- *Contract tests* over `deep-findings.json`: schema shape; every `id` present in
  the shipped catalog; at least one evidence item per non-`skipped` finding; no
  duplicate ids; `status` in the known union; evidence sanitized and length-capped.
- *Static assertion tests* over the target's source that mechanically back a
  finding — for example, enumerating `src/app/api/**/route.ts`, parsing the exported
  handlers, and asserting each one references an authorization helper before a data
  call. These are the scanner's code reading the target's source; they never execute
  the target's scripts.

`run-tests.mjs` is a thin `node --test` entry point with zero dependencies so it
runs in any target checkout regardless of that app's toolchain.

### The deep-check catalog (Phase 2)

Ids are namespaced `deep-` so they can never collide with a deterministic rule id,
and each gets a `docs/rules/<id>.md` page, preserving the existing stable-docs-URL
convention.

| Id | Severity | Question |
|---|---|---|
| `deep-api-route-authorization` | critical | Does every non-public API route enforce an auth/permission check before touching data? |
| `deep-tenant-scope-enforcement` | critical | Is every query in a tenant-scoped module filtered by the tenant/organization key? |
| `deep-untrusted-input-sinks` | high | Does request-derived input reach a shell, SQL template, path, or `fetch` sink without validation? |
| `deep-secret-handling-paths` | high | Are secrets read only through the config layer — never logged, never returned in a response? |
| `deep-dependency-advisory-reachability` | medium | For each lockfile advisory, is the vulnerable code path reachable from this app? |
| `deep-authz-test-coverage` | medium | Does the target's own suite assert the negative authorization cases? |

## Data Model

### `deep-findings.json` — written by the agent, read by the scanner

```json
{
  "deepSchemaVersion": 1,
  "packVersion": "0.2.0",
  "generatedAt": "2026-10-09T10:00:00.000Z",
  "agent": { "runner": "claude", "model": "opus", "runId": "a1b2c3d4" },
  "findings": [
    {
      "id": "deep-api-route-authorization",
      "status": "fail",
      "confidence": "high",
      "summary": "Two API routes read order data without an authorization check.",
      "evidence": [
        "src/app/api/orders/route.ts:12 exports GET and calls the order repository with no auth guard.",
        "src/app/api/orders/[id]/route.ts:9 exports GET with no auth guard."
      ]
    }
  ]
}
```

Validation is total: unknown top-level keys are rejected, `deepSchemaVersion` must
be `1`, `packVersion` must match the running scanner's shipped pack version (a
mismatch is a validation error naming both versions), `findings` must be an array of
objects whose `id` is in the catalog, `status` in `fail | warning | pass | skipped`,
`confidence` in `high | medium | low`, `summary` a non-empty string ≤ 400 chars, and
`evidence` an array of ≤ 10 strings each ≤ 240 chars.

### Report types (`src/types.ts`)

```ts
export type DeepConfidence = 'high' | 'medium' | 'low'

export type DeepRuleResult = RuleResult & { confidence: DeepConfidence }

export type DeepScanSection = {
  deepSchemaVersion: 1
  packVersion: string
  mode: 'run' | 'ingest'
  deterministic: false
  generatedAt: string
  agent: { runner: string; model: string | null; runId: string | null }
  results: DeepRuleResult[]
  summary: ScanSummary
}

export type ScanReport = {
  schemaVersion: 1
  tool: { name: '@open-mercato/mercato-readiness-scanner'; version: string }
  scannedAt: string
  target: string
  summary: ScanSummary
  results: RuleResult[]
  deepScan?: DeepScanSection   // the ONLY addition
}
```

`deepScan.results` is never merged into `results[]`, and `deepScan.summary` is
counted separately from `summary`. That is what lets `schemaVersion` stay `1`: a
consumer keying on `schemaVersion` and `results[].id`, exactly as the README
instructs, is unaffected.

### Sensitive-data handling

The findings file is agent-authored and therefore untrusted. `src/deep/sanitize.ts`
is applied to every `summary` and `evidence` string on ingest and enforces the same
guarantees the deterministic report already makes: control characters stripped,
absolute paths and `$HOME` prefixes rewritten to repo-relative, any `KEY=value`
fragment that looks like a credential replaced with `KEY=<redacted>`, and a hard
length cap. A finding whose evidence required redaction is downgraded to `warning`
and annotated, because redacted evidence cannot support a `fail`. This runs in the
scanner, never delegated to the agent's good behavior.

## API Contracts

### CLI additions

```
--deep-security <off|prepare|run|ingest>   default: off
--allow-agent-execution                    required by `run`; no effect otherwise
--deep-report <path>                       findings file for `ingest`
                                           (default: <target>/.ai/cezar/mercato-security/deep-findings.json)
--deep-model <model>                       passed through to cezar-run --model
--deep-timeout <seconds>                   default: 900
--deep-allow-dirty                         permit `run` against a dirty target worktree
--fail-on-deep <critical|high|medium|low|never>   default: never
```

All seven are additive; every existing flag keeps its current meaning. `--deep-*`
flags are usage errors (exit 2) when `--deep-security` is `off`, so a typo never
silently does nothing.

### Exit codes

`0`, `1`, `2`, and `3` keep today's meanings exactly. `--fail-on` continues to
consider deterministic failures only; `--fail-on-deep` is evaluated independently
and also yields `1`. One code is added:

- `4` — the deep phase did not produce a valid findings file (agent failed, timed
  out, wrote nothing, or wrote something that failed validation). The deterministic
  report has already been rendered and saved at this point.

### `prepare` output

`prepare` writes the pack, prints a per-file `written | unchanged | skipped (hand-edited)`
table, and prints the exact command to run next:

```
cezar-run run "Run the Open Mercato deep security audit and write .ai/cezar/mercato-security/deep-findings.json" \
  --repo /path/to/app --workflow mercato-security-audit
```

followed by the ingest command. Nothing is executed.

## UI/UX

Only one surface is new: a deep-findings block rendered after the existing
failed/review/skipped/passing groups, visually separated and captioned so a reader
cannot mistake an agent claim for a proven fact.

```
🤖 Deep security checks — agentic, NOT deterministic
   pack 0.2.0 · runner claude · model opus · cezar run 4f2a1c · 2026-10-09T10:00:00Z

  ❌ deep-api-route-authorization  (critical · confidence: high)
     Two API routes read order data without an authorization check.
     · src/app/api/orders/route.ts:12 exports GET and calls the order repository with no auth guard.
     · src/app/api/orders/[id]/route.ts:9 exports GET with no auth guard.
     → https://github.com/open-mercato/mercato-readiness-scanner/blob/main/docs/rules/deep-api-route-authorization.md

  ⚠️ deep-tenant-scope-enforcement  (critical · confidence: medium)
     …

  These findings come from an AI agent run. Confirm each one against the source
  before treating it as fact. They do not affect --fail-on (see --fail-on-deep).
```

Markdown mirrors this under `## Deep security checks (agentic, not deterministic)`
with the same caveat sentence and the same metadata line. In `off` mode — the
default — every byte of terminal, Markdown, and JSON output is identical to today;
this is asserted by a regression test against the existing fixtures rather than
left to review.

Accessibility and non-TTY: the emoji markers follow the existing
`❌ / ⚠️ / ⏭️ / ✅` convention and are always accompanied by the rule id, the
severity word, and the confidence word, so nothing depends on the glyph. `run`
requires an explicit consent flag, so there is never an interactive prompt to miss
in CI.

## Edge Cases & Failure Scenarios

| Scenario | Behavior |
|---|---|
| `cezar-run` not on `PATH` | `prepare` and `ingest` work normally. `run` exits 2 naming the missing binary and the install command. Never a silent skip. |
| Target is not a git repository | `run` refuses with exit 2: cezar's per-task worktree is the containment boundary, and without it the agent would edit the operator's checkout directly. |
| Target worktree is dirty | `run` refuses with exit 2 unless `--deep-allow-dirty`; otherwise the agent's commits interleave with the operator's uncommitted work. |
| Pack already present at a different version | Generated files (header matched) are overwritten and the version change is reported. A hand-edited file is left untouched and reported `skipped (hand-edited)`; the run continues. |
| Pack directory not writable | `prepare` / `run` exit 2 naming the path. The deterministic report is unaffected. |
| Agent exits non-zero, times out, or writes nothing | Exit 4 with the cezar run id so the operator can read the event log. The deterministic report was already rendered and saved. |
| Findings file fails validation | Exit 4, every validation error listed. **Never partially ingested** — the `deepScan` section is omitted entirely rather than shown half-trusted. |
| Finding names an id outside the catalog | Dropped, and a `warning`-level ingest note lists the dropped ids. The agent cannot invent a rule into the report. |
| Finding `status: fail` with zero evidence | Downgraded to `warning` on ingest. A failure assertion with no evidence is an opinion. |
| Evidence contains an absolute path, `$HOME`, or a `KEY=value` secret | Redacted by the sanitizer and the finding downgraded to `warning`. Enforced in the scanner, not trusted to the agent. |
| `packVersion` mismatch between file and scanner | Validation error (exit 4) naming both versions — a stale findings file must not be rendered as current. |
| Target app source contains instructions addressed to the agent (prompt injection) | The skill states the boundary, but the design does not rely on it. The ingest validator is the backstop: agent output can only ever become a catalog finding with sanitized evidence — never a new rule, never a mutated deterministic result, never a report field outside `deepScan`. |
| Agent tries to write outside the pack directory | Not prevented by `allowedTools` (cezar's default `Bash` is unrestricted), and explicitly acknowledged as such. Mitigation is the worktree boundary — the writes land in a throwaway cezar worktree, not the operator's checkout — plus the ingest validator, which reads exactly one path. |
| Deterministic scan itself fails | Unchanged: exit 3, deep phase never starts. |

## Risks & Impact Review

**The scanner stops being purely read-only and deterministic — the central risk.**
`AGENTS.md` currently says "Never execute target application scripts", "Keep findings
deterministic", and "Ask before adding active network probes or executing code from a
scanned application". This feature does not execute the *target's* code, but it does
execute an LLM agent with shell access inside a checkout of the target. Mitigations:
default `off`; the deterministic report is unchanged and rendered **first**; agentic
results are segregated, captioned, and carry `deterministic: false` and a
`confidence`; they are excluded from `--fail-on`; `run` needs a second explicit
consent flag and ships last; and `AGENTS.md` gains an explicit amendment covering
agent-delegated checks (Phase 4, step 16). Approving this spec is approving that
amendment — this is Q3's `⚠ NEEDS HUMAN CONFIRMATION`.

**Cost.** Every `run` spends the operator's agent subscription. Mitigations: never
automatic, bounded by `--deep-timeout`, `prepare` is the zero-cost path, and the run
prints whatever token/cost usage cezar reports.

**Trust inflation.** A human seeing `❌` may treat an LLM claim as proven. Mitigations:
the caption, the per-finding `confidence`, the mandatory evidence (and the downgrade
when it is missing or redacted), `deterministic: false` in JSON, and the separate
failure gate.

**Pack rot.** The shipped workflow/skill/tests can drift from the cezar version in
use. Mitigation: Phase 4 runs the pack's contract tests in this repo's CI with
`CEZ_DRY_RUN=1`, so the pack is exercised on every push without spending tokens.

**Backward compatibility.** Protected surfaces and their treatment: the JSON report
gains one **optional** field and keeps `schemaVersion: 1`; `docs/report.schema.json`
adds `deepScan` as optional; the CLI gains seven additive flags and one new exit
code (`4`) on a path that cannot be reached without opting in; the three formatters'
`off`-mode output is asserted byte-identical. No existing behavior changes, so
nothing here is a breaking change.

**Rollback.** Delete `src/deep/`, `assets/deep-pack/`, the flags, the optional type
field, and the schema property. There is no migration and no persisted state except
the generated pack inside the target's `.ai/cezar/`, which `prepare` already reports
as generated and which a `--deep-security=prepare --clean` follow-up (out of scope
here) or a manual delete removes.

## Phasing

- **Phase 1 — contract and plumbing (`prepare` + `ingest`).** The scanner never
  spawns an agent. Ships the types, the validator, the sanitizer, the ingest path,
  the catalog scaffold, the pack materializer, the renderer, and the schema update.
  Independently shippable and immediately useful: an operator runs `cezar-run` by
  hand and gets the findings in the report.
- **Phase 2 — the check pack.** The six deep checks: skill playbook, workflow,
  `run-tests.mjs`, contract tests, per-rule static assertion tests, catalog entries,
  and one `docs/rules/deep-*.md` page each.
- **Phase 3 — `run` mode.** Spawning `cezar-run` behind `--allow-agent-execution`,
  the preflight, the timeout, exit code `4`, and cost reporting.
- **Phase 4 — docs and CI.** README section, the `AGENTS.md` amendment, a GitHub
  Actions recipe that ingests findings from a separate agent job, and the pack's
  contract tests wired into this repo's CI under `CEZ_DRY_RUN=1`.

Out of scope, deliberately, for a later spec: live/dynamic probing (booting the
target app, HTTP requests against a running instance), auto-fixing findings, opening
remediation PRs, and adding a third-party SAST as a second evidence source.

## Implementation Plan

Each step leaves `npm run check` green and the application working.

### Phase 1 — contract and plumbing

1. **Types.** Add `DeepConfidence`, `DeepRuleResult`, `DeepScanSection` to
   `src/types.ts` and the optional `ScanReport.deepScan`. *Test:* a fixture report
   with and without `deepScan` round-trips through `formatJson`.
2. **Catalog scaffold.** `src/deep/catalog.ts` — the `deep-` rule metadata table
   (typed, empty in this phase) reusing the `docsUrl` derivation from `src/rules.ts`.
   *Test:* every id matches `^deep-[a-z0-9-]+$` and has a matching
   `docs/rules/<id>.md`, mirroring the existing rules-docs test.
3. **Validator.** `src/deep/schema.ts` — total validator returning
   `{ok: true, value}` or `{ok: false, errors}`. No new dependency. *Tests:* valid
   fixture; each required field missing; wrong types; unknown top-level key; unknown
   rule id; `packVersion` mismatch; oversized summary and evidence.
4. **Sanitizer.** `src/deep/sanitize.ts` — control characters, absolute/`$HOME`
   paths, `KEY=value` redaction, 240-char cap. *Tests:* one per rule, plus the
   downgrade-to-`warning` behavior when redaction fired.
5. **Ingest.** `src/deep/ingest.ts` — file → `DeepScanSection`, catalog lookup for
   title/category/severity/remediation/docsUrl, own `summary` counts, dropped-id
   notes, evidence-less `fail` downgrade. *Tests:* happy path; unknown id dropped;
   empty findings; missing file.
6. **Pack materializer.** `src/deep/pack.ts` — copy `assets/deep-pack/` into the
   target, write the generated-by header, detect hand-edits, return a per-file
   `written | unchanged | skipped` report; idempotent. *Tests:* fresh dir, re-run,
   hand-edited file preserved, unwritable dir.
7. **CLI.** `src/cli.ts` — `--deep-security off|prepare|ingest`, `--deep-report`,
   `--fail-on-deep`; reject `--deep-*` flags when the mode is `off`; `prepare` prints
   the pack table and the `cezar-run` command. *Tests:* extend `test/cli.test.ts` for
   each flag, each usage error, and the `prepare` output.
8. **Formatters.** `src/formatters.ts` — render `deepScan` in terminal, Markdown, and
   JSON with the caption and metadata line. *Tests:* a deep-section snapshot per
   format, plus a regression assertion that `off`-mode output is unchanged against
   the existing fixtures.
9. **Schema.** `docs/report.schema.json` — add `deepScan` as an optional property
   with its `$defs`; `schemaVersion` stays `1`. *Test:* the deep fixture report
   validates against the schema.

### Phase 2 — the check pack

10. **Skill.** `assets/deep-pack/skills/mercato-security-audit.md` — one section per
    catalog id with its required evidence, the output contract, the evidence rules,
    and the prohibitions. *Test:* a lint test asserting the file names every catalog
    id and contains the prohibition block.
11. **Workflow.** `assets/deep-pack/workflows/mercato-security-audit.yaml` — the
    audit + assert steps with `onFail: {retry: audit, max: 2}`. *Test:* parse it with
    the already-present `yaml` dependency and assert the step ids, the `skill`
    reference, and the check command path.
12. **Test runner and contract tests.** `run-tests.mjs` plus
    `tests/contract.test.mjs`. *Test:* run the pack's own suite from this repo's
    suite against a good fixture (passes) and a bad fixture (fails with the expected
    message).
13. **The six checks.** Catalog entries in `src/deep/catalog.ts`, one static
    assertion test each in the pack, one `docs/rules/deep-*.md` page each, and a
    "Deep security checks" section added to the README rule catalog. *Test:* the
    step-2 docs test now covers six real ids; each assertion test runs against a
    fixture app with a known-good and a known-bad variant.

### Phase 3 — `run` mode

14. **Invoker.** `src/deep/invoke.ts` — preflight (git repo, clean tree, binary
    resolvable, consent flag), `spawnSync` with an argument array and no shell,
    environment allowlist, inherited stdio, timeout, captured run id and reported
    cost. *Tests:* a stub `cezar-run` on `PATH` for success, non-zero exit, timeout,
    and each preflight refusal.
15. **CLI wiring.** `run` mode, `--allow-agent-execution`, `--deep-model`,
    `--deep-timeout`, `--deep-allow-dirty`, exit code `4`; the deterministic report
    is rendered and saved before the agent starts. *Tests:* with the stub — refusal
    without consent, success path, exit 4 on agent failure, and deterministic output
    still produced when the agent fails.

### Phase 4 — docs and CI

16. **Docs.** README "Deep security checks" section (the four modes, the consent
    flag, the non-determinism caveat, the CI recipe) and the `AGENTS.md` amendment
    adding agent-delegated checks to the Ask-First list and clarifying that the
    "never execute" rule covers the target's scripts, not the scanner's own tests.
17. **CI.** Extend `.github/workflows/test.yml` to run the pack's contract tests with
    `CEZ_DRY_RUN=1` so the pack cannot rot unnoticed, and add the deep fixture to the
    schema-validation job.
