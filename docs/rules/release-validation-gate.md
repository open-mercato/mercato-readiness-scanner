# Release validation gates the exact revision

**Rule ID:** `release-validation-gate`
**Severity:** High

Generation, the production build, relevant tests, and migration verification
must block the exact revision or artifact that reaches production. A command
that ran locally against another commit is not release evidence.

## Remediation

Add one release-triggered blocking job that runs generation, build, tests, and
migration review for the same revision. Pull-request-only checks, commands split
across unrelated workflows, and `continue-on-error` do not prove the release is
gated. Retain the results and deploy only the validated revision.

See [Validate the release before production traffic](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
