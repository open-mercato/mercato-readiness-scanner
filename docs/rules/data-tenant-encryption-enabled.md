# Tenant database field encryption is enabled

**Rule ID:** `data-tenant-encryption-enabled`
**Severity:** Critical

Requires an explicit true/yes/on/1 TENANT_DATA_ENCRYPTION setting. This checks application field-encryption configuration, not provider disk encryption, SQL connection TLS, existing row ciphertext, encryption maps, or completed backfills.

Environment checks inspect production dotenv files and the scanner process environment locally. Evidence contains setting names and fixed descriptions only. Values are never included in reports.

## Remediation

Explicitly set TENANT_DATA_ENCRYPTION=yes and verify encryption maps and backfill completion. Provider disk encryption and database TLS require separate verification.

See [deployment checks](../deployment.md) for precedence, Railway, GitHub Actions, and rule selection.
