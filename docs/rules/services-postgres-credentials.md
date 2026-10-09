# PostgreSQL uses explicit non-default credentials

**Rule ID:** `services-postgres-credentials`
**Severity:** Critical

Inspects DATABASE_URL for a valid PostgreSQL URL, explicit role, and a non-default password of at least 16 characters. Rejects POSTGRES_HOST_AUTH_METHOD=trust and weak explicit POSTGRES_PASSWORD values. Conventional administrator role names need review. No connection or login is attempted.

Environment checks inspect production dotenv files and the scanner process environment locally. Evidence contains setting names and fixed descriptions only. Values are never included in reports.

## Remediation

Set DATABASE_URL with a dedicated database role and a strong unique password. Disable trust authentication and resolve substitutions. Verify least privilege and database TLS separately.

See [deployment checks](../deployment.md) for precedence, Railway, GitHub Actions, and rule selection.
