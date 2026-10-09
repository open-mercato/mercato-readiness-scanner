# Browser and real-time origins are restricted

**Rule ID:** `edge-allowed-origins`
**Severity:** High

Browser APIs, checkout, and collaborative documents should accept only intended
HTTPS origins. Wildcards or sibling domains can expose authenticated or
real-time capabilities to an untrusted site.

## Remediation

Configure `APP_ALLOWED_ORIGINS` and, when enabled,
`CHECKOUT_ALLOWED_ORIGINS` and `DOCUMENTS_COLLAB_ALLOWED_ORIGINS`. Use exact
production origins and verify rejected-origin behavior at the deployed edge.

See [Lock down operator and application access](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
