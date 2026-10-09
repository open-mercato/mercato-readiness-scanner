# A deployment health check is wired

**Rule ID:** `operations-health-check`
**Severity:** High

The standard `/api/healthz` endpoint lets the platform remove an unhealthy
release and lets operators monitor availability. Merely having the framework
route is insufficient if the deployment platform does not probe it or dependency
failures still return a healthy response.

## Remediation

Configure the provider to probe `/api/healthz` with bounded timeouts and failure
thresholds. Test healthy, dependency-failure, and recovery behavior, and add an
external HTTPS monitor for the public route. The scanner recognizes structured
Railway health-check configuration and Compose health-check commands; logging or
echoing the route is not wiring.

See [Make the deployment observable](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
