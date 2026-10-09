# Release validation gates the exact revision

**Rule ID:** `release-validation-gate`
**Severity:** High

Generation, the production build, relevant tests, and migration verification
must block the exact revision or artifact that reaches production. A command
that ran locally against another commit is not release evidence.

## Remediation

Add blocking CI stages for generation, build, tests, and migration review. Avoid
`continue-on-error` on required release evidence, retain the results, and deploy
only the validated revision.

See [Validate the release before production traffic](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
