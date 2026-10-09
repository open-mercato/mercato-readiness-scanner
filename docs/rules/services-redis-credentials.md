# Redis connections require authentication

**Rule ID:** `services-redis-credentials`
**Severity:** High

Checks every supplied REDIS_URL and role-specific *_REDIS_URL for redis/rediss syntax and a non-default password of at least 16 characters. Redis referenced in deployment files or CACHE_STRATEGY=redis requires a connection URL. Authentication, ACLs, TLS negotiation, and service availability are not probed.

Environment checks inspect production dotenv files and the scanner process environment locally. Evidence contains setting names and fixed descriptions only. Values are never included in reports.

## Remediation

Set authenticated Redis URLs for every cache, event, queue, and collaboration connection. Use strong unique passwords or ACL credentials, private networking, and TLS where required.

See [deployment checks](../deployment.md) for precedence, Railway, GitHub Actions, and rule selection.
