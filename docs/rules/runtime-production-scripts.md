# Production build and start scripts are explicit

**Rule ID:** `runtime-production-scripts`
**Severity:** High

Repeatable production builds need an explicit `build` command, an explicit
`start` command, and production mode during compilation. Development servers are
not production process managers.

## Remediation

Retain the generated build and start scripts, including explicit
`NODE_ENV=production` for the build. Run generation and the build for the exact
release artifact before deployment.

## Automatic fix

`mercato-readiness apply` can partly fix this rule: it inserts a missing `build` or `start` key
into `package.json` and never changes an existing value. Review the inserted `build` command — the
generated default assumes `next build` — and if your existing `build` does not force
`NODE_ENV=production`, that half stays a manual edit.

See [Validate the release before production traffic](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
