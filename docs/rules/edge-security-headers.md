# Application security headers are configured

**Rule ID:** `edge-security-headers`
**Severity:** High

The generated Next.js configuration provides the baseline Content Security
Policy, referrer policy, frame protection, and MIME-sniffing protection.
Provider configuration must preserve those headers.

## Remediation

Keep the shared header baseline in `next.config.ts`, add provider origins only
when a feature requires them, and inspect public responses for
`Content-Security-Policy`, `Referrer-Policy`, frame protection, and
`X-Content-Type-Options` after deployment. Configure HSTS at the TLS-owning edge.

See [Lock down operator and application access](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
