# Agent guidelines

## Always

- Keep `scan` read-only with respect to the scanned application. `scan` is the default command
  and must never create, modify, or delete a file in the target. The only exception to the
  read-only invariant is the explicit, opt-in `apply` command described below.
- Keep credential values out of tools, logs, reports, prompts, and evidence. Never read private-key files, token caches, or secret stores.
- Scans inspect credentials by default, as explicitly requested by the user. Inspect only bounded local production dotenv files, Compose settings, and visible runtime configuration in memory. Never run scans on a real application during development; use synthetic fixtures and the isolated test environment provided by npm test. Never follow links or upload values. `apply` explicitly disables credential inspection and retains its no-credential-reading rule.
- Keep findings deterministic and evidence free of secret values and absolute home paths.
- Give every rule a stable ID and its own matching `docs/rules/<rule-id>.md` page.
- Preserve the JSON schema version and document incompatible report changes.
- Run `npm run check` before committing.

## The `apply` carve-out

`mercato-readiness apply` is the one, narrowly scoped, user-requested exception to the read-only
invariant. It exists so the remediations the scanner reports can actually be landed. Every bound
below is part of the contract — do not widen any of them without an explicit request.

- Mutation is reachable only through the explicit `apply` subcommand. `scan` with any combination
  of its own flags still writes nothing to the target.
- `apply` refuses to run unless the target is a git working tree, and refuses a worktree with
  uncommitted changes unless `--allow-dirty` is passed. Git is the user's only undo.
- `apply` never prompts when stdin is not a TTY; without `--yes` / `--non-interactive` there it
  exits 2 with a usage error.
- Every rule in `src/rules.ts` carries an explicit `autofix` descriptor, so each one is
  deliberately classified `safe-additive` or `manual-only`. A new rule cannot compile without it.
- `safe-additive` means purely additive and impossible to lose data with: create a file that does
  not exist, append a line that is absent, insert a missing key. The writers refuse symlinks,
  paths outside the application root, and any `.env*` or credential path; files are created with
  `wx` and appended with `a`, so existing content is never overwritten or truncated. The
  `package.json` script insert only happens when the file round-trips byte-for-byte through
  `JSON.parse`/`JSON.stringify`, which proves the inserted key is the only difference.
- Everything else stays `manual-only` and is reported as skipped with its reason and docs URL.
- `apply --mode agent` delegates to the `cezar-run` CLI and nothing else. Never shell out to
  `codex` or `claude` directly, and never hardcode a model or provider.
- `apply` still never runs the target application's scripts and still never reads a value-bearing
  `.env*` file.

## Ask First

- Ask before publishing to npm, making the repository public, or adding a runtime dependency.
- Ask before adding active network probes or executing code from a scanned application.

## Never

- Never execute target application scripts, in `scan` or in `apply`.
- Never write to the scanned application outside the `apply` carve-out above.
- Never upload scan results or target files.
- Never claim that a static check proves live infrastructure state.
