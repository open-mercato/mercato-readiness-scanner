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

See [Validate the release before production traffic](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
