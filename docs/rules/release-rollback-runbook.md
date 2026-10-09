# Rollback and forward-fix procedures are documented

**Rule ID:** `release-rollback-runbook`
**Severity:** High

Application rollback does not automatically reverse database migrations, queued
jobs, or changed configuration. Operators need a provider-specific decision and
execution path before a release fails.

## Remediation

Keep the prior immutable artifact and configuration, document authorized
provider commands and abort thresholds, classify migration compatibility, and
define worker and traffic handling. Rehearse rollback or forward-fix recovery in
a production-like environment.

## Automatic fix

`mercato-readiness apply` can create a `docs/runbooks/rollback-and-forward-fix.md` stub when no
rollback runbook exists. The stub is a TODO checklist: it moves this rule to ⚠️ *review*, and only
a rehearsal against the actual provider can satisfy it.

See [Prepare and rehearse rollback](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
