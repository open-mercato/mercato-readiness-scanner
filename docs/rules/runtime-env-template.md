# Production configuration has a sanitized template

**Rule ID:** `runtime-env-template`
**Severity:** High

A release-specific `.env.example` makes required configuration names auditable
without exposing live values. The scanner expects the core production settings
`NODE_ENV`, `APP_URL`, `DATABASE_URL`, `INTERNAL_APP_ORIGIN`, and
`PLATFORM_PRIMARY_HOST` to be represented.

## Remediation

Create or update `.env.example` with names, empty values or unmistakably safe
placeholders, and useful comments only. Compare it with the exact deployed
release. Do not copy credential-bearing URLs, live credentials, or
environment-specific secrets into the template.

See [Prepare the production environment and secrets](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
