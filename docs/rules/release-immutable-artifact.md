# Production deploys select an immutable artifact

**Rule ID:** `release-immutable-artifact`
**Severity:** High

A production release and its rollback must identify exactly what was built.
Tags such as `latest`, `main`, or `develop` can move after approval and cannot
serve as durable release evidence.

## Remediation

Build once and deploy by content digest or commit-derived identifier. Record the
artifact with the configuration revision and migration set, and retain the prior
compatible artifact without rebuilding from a moving branch.

See [Plan and execute a controlled rollout](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
