# Exactly one package lockfile is committed

**Rule ID:** `supply-chain-single-lockfile`
**Severity:** Medium

Competing package-manager lockfiles make local, CI, and deployment resolution
ambiguous. A generated app should have one source of truth.

## Remediation

Choose the supported package manager, commit its lockfile, remove competing
lockfiles, and align local, CI, image, and provider build commands with that
choice.

See [Validate the release before production traffic](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
