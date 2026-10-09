# Effective environment targets production

**Rule ID:** `runtime-production-environment`
**Severity:** High

Checks NODE_ENV=production, HTTPS APP_URL, explicit HTTPS origin allowlists, and a non-negative integer RATE_LIMIT_TRUST_PROXY_DEPTH. Unreadable production dotenv files and unresolved substitutions fail. Templates never substitute for live settings. The correct proxy-hop count still requires topology knowledge.

Environment checks inspect production dotenv files and the scanner process environment locally. Evidence contains setting names and fixed descriptions only. Values are never included in reports.

## Remediation

Run in the deployed process environment. Set NODE_ENV=production, a canonical HTTPS APP_URL, explicit origin allowlists, and the exact trusted proxy depth. Resolve environment substitutions.

See [deployment checks](../deployment.md) for precedence, Railway, GitHub Actions, and rule selection.
