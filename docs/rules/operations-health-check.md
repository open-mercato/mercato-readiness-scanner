# A deployment health check is wired

**Rule ID:** `operations-health-check`
**Severity:** High

The standard `/api/healthz` endpoint lets the platform remove an unhealthy
release and lets operators monitor availability. Merely having the framework
route is insufficient if the deployment platform does not probe it.

## Remediation

Configure the provider to probe `/api/healthz` with bounded timeouts and failure
thresholds. Test healthy, dependency-failure, and recovery behavior, and add an
external HTTPS monitor for the public route.

See [Make the deployment observable](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
