# Production containers run as non-root

**Rule ID:** `container-non-root-user`
**Severity:** High

A non-root final image limits the impact of an application compromise. The
scanner checks the final effective `USER` directive when a Dockerfile is
present; non-container deployments are marked not applicable.

## Remediation

Create a dedicated unprivileged runtime user, give it only the required files,
and make the final production stage end with `USER <name-or-id>`. Verify mounted
volumes remain writable only where intended.

See [Provision and isolate the infrastructure](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
