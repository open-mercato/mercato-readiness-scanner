# Trusted proxy depth is topology-specific

**Rule ID:** `edge-trusted-proxy-depth`
**Severity:** High

Client-address and rate-limit logic can be bypassed when an application trusts
arbitrary forwarded headers. The trusted hop count must match the actual ingress
chain.

## Remediation

Document `RATE_LIMIT_TRUST_PROXY_DEPTH` in the sanitized configuration template,
set its live value to the exact number of trusted proxies, and test spoofed and
legitimate forwarded-address scenarios through the real edge.

See [Production Readiness](https://docs.openmercato.com/deployment/production-readiness).
