# Sensitive local files are ignored

**Rule ID:** `secrets-ignore-policy`
**Severity:** High

The repository ignore policy should explicitly cover `.env.production`, local
environment variants, private keys, local MCP and npm credentials, and raw agent-session exports. This is a guardrail
against accidental commits, not a substitute for secret scanning or credential
rotation.

## Remediation

Add narrowly scoped patterns for `.env`, `.env.production`, `.env.local`,
`.env.*.local`, `*.pem`, `*.key`, `.mcp.json`, `.npmrc`, and
`.ai/session-exports/`. Keep explicit exceptions only for sanitized templates.
Verify the policy with `git check-ignore` before handling production values.

## Automatic fix

`mercato-readiness apply` can fix this rule: it appends only the missing patterns to
`.gitignore`, or creates the file when it is absent. Existing lines are never rewritten, and the
exceptions you keep for sanitized templates are left alone.

See [Prepare the production environment and secrets](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
