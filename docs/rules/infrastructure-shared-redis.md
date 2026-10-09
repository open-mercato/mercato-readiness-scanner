# Multi-process deployments use shared Redis coordination

**Rule ID:** `infrastructure-shared-redis`
**Severity:** High

Separate web and worker processes cannot safely coordinate cache invalidation,
events, or asynchronous queues through memory, a local file, or SQLite. They
must share the same production Redis service.

## Remediation

Select the Redis cache strategy, document the supported Redis configuration
names in the sanitized template, and connect every web and worker replica to the
same private service. Verify live queue and invalidation behavior after deploy.

See [Provision and isolate the infrastructure](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
