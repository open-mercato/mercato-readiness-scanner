# Background workers have an explicit process topology

**Rule ID:** `operations-worker-topology`
**Severity:** High

Queue-backed work needs separately supervised workers in a multi-process
production deployment. Web-process auto-spawn and dedicated workers must not
compete for the same operational role.

## Remediation

Deploy the supported worker command separately with the same release and
compatible configuration as the web process. Disable conflicting auto-spawn,
exercise a test job, and alert on worker absence, retries, and queue growth.

See [Queue & Workers](https://docs.openmercato.com/framework/events/queue-workers).
