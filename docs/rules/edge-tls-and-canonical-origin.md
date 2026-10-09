# TLS and canonical origin are verified at deployment

**Rule ID:** `edge-tls-and-canonical-origin`
**Severity:** Critical

All public traffic must use the intended HTTPS hostname. Certificates, renewal,
DNS, redirects, callback URLs, cookies, and the application's canonical origin
must agree. Static repository evidence cannot prove the live edge, so a detected
runbook still requires operator verification.

## Remediation

Install a complete certificate chain, automate renewal, redirect HTTP to HTTPS,
remove unintended public ports, and set `APP_URL` plus topology-specific origins
to the final HTTPS URL. Test from outside the hosting network.

See [Production Readiness](https://docs.openmercato.com/deployment/production-readiness).
