# Database migrations are part of release startup

**Rule ID:** `release-database-migrations`
**Severity:** High

Application code and database schema must advance in a controlled order. A
multi-replica deployment must not race the same migration from every instance.

## Remediation

Run the supported migration command from exactly one controlled release job
before accepting traffic; do not let every web or worker replica race it.
Assign ownership, capture output, take the required backup, and verify that the
schema and application versions are compatible before scaling the web and
worker processes. The command must be executable and failure-preserving;
comments, echo statements, and masked commands are not release evidence.

See [Provision and isolate the infrastructure](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
