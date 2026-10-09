# Web and worker processes use the same release artifact

**Rule ID:** `workers-release-parity`
**Severity:** High

Web and worker processes can exchange incompatible jobs or data when deployed
from different source revisions, images, Dockerfiles, or dependency locks.

## Remediation

Build one immutable artifact and deploy it to both roles, changing only the
supported entrypoint and role-specific configuration. Keep rollout ordering
compatible while versions overlap and verify both report the intended release.

See [Run production workers and choose durable storage](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
