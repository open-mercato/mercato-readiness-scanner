# Live environment files are not tracked

**Rule ID:** `secrets-live-env-untracked`
**Severity:** Critical

Value-bearing `.env*` files can expose database credentials, signing secrets,
provider tokens, and encryption material to every person and system with source
access. The scanner asks Git only for tracked path names; it never opens those
files or reports their values. Sanitized `.env.example`, `.env.sample`, and
`.env.template` files are allowed.

## Remediation

Remove live environment files from version control and history as appropriate,
rotate every potentially exposed credential, then keep live values in the
deployment platform's secret store. Confirm that only sanitized templates remain
tracked.

See [Prepare the production environment and secrets](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
