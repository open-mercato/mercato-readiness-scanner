# Execution brief — policy apply mode (direct + cezar-run delegation)

Read this file in full before writing code. Also read `README.md` and `AGENTS.md`.

## Context

Today this repo is a strictly read-only static scanner. `node dist/cli.js scan <target>`
evaluates the rules in `src/rules.ts` and reports findings with remediation text and a
permanent docs URL per rule.

Relevant surfaces:

- `src/cli.ts` — argument parsing, exit codes, output selection
- `src/scan.ts` — scan orchestration
- `src/rules.ts` — the rule definitions
- `src/formatters.ts` — terminal / markdown / JSON rendering
- `src/files.ts`, `src/app.ts`, `src/types.ts` — IO helpers, target detection, types
- `docs/rules/<rule-id>.md` — one documentation page per rule
- `docs/report.schema.json` — versioned JSON report contract
- `test/cli.test.ts`, `test/scanner.test.ts`, `test/policies.test.ts`, `test/fixture.ts`

Exit-code convention already in use: `0` success, `1` severity threshold tripped via
`--fail-on`, `2` invalid usage or invalid target, `3` unexpected scanner/output failure.

## Goal

Two new ways to actually **apply** the remediations to the scanned project.

### (A) Direct apply, performed by the CLI itself

- Add an explicit CLI option/subcommand that applies policies to the target project, plus
  an interactive confirmation question when running on a TTY: show what will change, then
  ask before writing anything.
- There MUST be a documented non-interactive path for CI: an explicit flag
  (`--yes` / `--non-interactive`) that skips all prompts. Never prompt when stdin is not a
  TTY — in that case, without the flag, exit `2` with a clear usage error.
- **Hard precondition.** Refuse to apply anything unless the target project is a git
  working tree (`git rev-parse --is-inside-work-tree`). If it is not, print a clear
  actionable error and exit non-zero. Git is the user's only undo for these writes.
- Also refuse when the target worktree has uncommitted changes, unless an explicit
  override flag is passed, so the user can always diff and revert exactly what was written.
- **Only apply policies that are SAFE and cannot cause data loss.** Classify this per rule
  in `src/rules.ts` via an explicit autofix descriptor carrying a safety class, so that
  every single rule is deliberately marked either auto-fixable-safe or manual-only.
  - Safe means purely additive and non-destructive: create a file that does not exist,
    append a missing entry to `.gitignore`, add a missing npm script key, write a missing
    docs/runbook stub.
  - NEVER overwrite or truncate existing file content. Never delete or rewrite existing
    config. Never touch `.env*` values or anything secret-bearing — the secret-handling
    rules in `AGENTS.md` still apply in full. Never run the target project's scripts.
  - Anything not provably safe stays manual-only and is reported as skipped-manual with
    its docs URL.
- Report what was changed, and what was skipped and why.
- Must be idempotent: a second run against an already-fixed project is a no-op.

### (B) Delegate the apply to an AI coding agent, via `cezar-run` ONLY

- A second mode which, instead of writing files itself, builds a prepared remediation
  prompt from the scan results and hands it to the `cezar-run` CLI.
- Invoke `cezar-run`. Do **not** shell out to `codex` or `claude` directly, and do not
  hardcode any model or provider.
- The prompt must carry the report: either a path/link to the report the CLI just saved
  (reuse the existing `--markdown` / `--json` / `--output` machinery) or the report content
  inlined. Prefer referencing the saved file when one exists; inline otherwise.
- Support emitting the prompt without executing anything (`--print-prompt` / `--dry-run`)
  so it is inspectable and testable.
- Require confirmation before actually spawning `cezar-run` in interactive mode; the same
  non-interactive flag applies for CI.
- Resolve the `cezar-run` binary in a configurable, overridable way (env var or flag)
  rather than assuming a global `PATH` entry.

## Constraints

- `scan` with no new flags must stay byte-for-byte read-only: zero behaviour change on the
  existing happy path. All mutation sits behind the new explicit option only.
- `AGENTS.md`'s first rule is "Keep the scanner read-only with respect to the scanned
  application." This feature is an intentional, user-requested carve-out. Update
  `AGENTS.md` so both the invariant and its narrow, opt-in exception are documented
  truthfully. Do not silently contradict it.
- Preserve the `docs/report.schema.json` version contract. If the report shape changes,
  version it and document the change.
- Document BOTH new modes in `README.md`, including a copy-pasteable CI (non-interactive)
  invocation.
- Do not add a runtime dependency without saying so prominently in your report
  (`AGENTS.md` marks that "ask first"); prefer Node built-ins for prompting and spawning.

## Tests — integration tests are explicitly required

Build real temporary git repositories as fixtures (extend `test/fixture.ts`; the suite runs
as `npm test` → `node --import tsx --test test/*.test.ts`).

Cover at minimum:

1. Non-git target is refused, with the right exit code and message.
2. Dirty worktree is refused without the override flag.
3. Safe policies are actually applied and the resulting files on disk are correct.
4. Manual-only policies are not touched.
5. A second run is a no-op (idempotence).
6. Non-TTY without the explicit flag errors instead of hanging on a prompt.
7. Non-TTY with the flag succeeds.
8. The `cezar-run` delegation builds the expected prompt and references the saved report —
   with a **stubbed** `cezar-run` binary. Never invoke a real agent from a test.

Keep `test/cli.test.ts`, `test/scanner.test.ts` and `test/policies.test.ts` green.

## Done means

- `npm run check` passes end to end (typecheck, test, build, test:built, pack:check,
  registry:check).
- Work is committed on your own branch in clear conventional commits.
- Your report states which rules you classified as safe-autofixable vs manual-only, and why.
- Do **not** open a pull request and do **not** push to `main` — the parent task merges
  your branch and handles the PR.

## Progress

PR: #2

- [x] Phase 1: per-rule autofix safety classification — 33e9dfc
- [x] Phase 2: additive-only writer + git preconditions — ad30ac3
- [x] Phase 3: apply subcommand, direct and cezar-run modes — d2870be
- [x] Phase 4: integration tests on real temp git repos — 5d4d8ec
- [x] Phase 5: README + AGENTS.md carve-out — 19a53da
- [x] Post-review fix: align secrets-ignore autofix with main's effective-coverage check; add `force` append and its regression test — 3f5ddf2
