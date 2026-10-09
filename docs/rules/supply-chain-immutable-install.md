# Deployments use immutable dependency installation

**Rule ID:** `supply-chain-immutable-install`
**Severity:** High

An immutable install makes the lockfile authoritative and prevents dependency
resolution from drifting during a build.

## Remediation

Commit one lockfile and use the matching strict command in deployment builds:
`yarn install --immutable`, `npm ci`, or `pnpm install --frozen-lockfile`.
Treat an unexpected lockfile change as a reviewed source change.

See [Validate the release before production traffic](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
