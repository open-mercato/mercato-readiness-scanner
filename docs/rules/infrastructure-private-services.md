# Stateful services are not publicly published

**Rule ID:** `infrastructure-private-services`
**Severity:** Critical

PostgreSQL, Redis, search, and internal worker services should not have an
all-interface host binding. Repository evidence can detect unsafe Compose
bindings but cannot prove an external provider firewall.

## Remediation

Remove public port publication and connect application processes over private
networks. Use an authenticated, audited operator tunnel when direct
administration is required, then verify the live provider firewall separately.

See [Provision and isolate the infrastructure](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
