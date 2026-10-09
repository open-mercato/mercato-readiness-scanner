# Encryption has an independent fallback key

**Rule ID:** `data-encryption-key-config`
**Severity:** Critical

Requires an explicit fallback passphrase of at least 32 characters in TENANT_DATA_ENCRYPTION_FALLBACK_KEY or its supported TENANT_DATA_ENCRYPTION_KEY alias. Rejects weak defaults, signing-secret reuse, and ALLOW_DERIVED_KMS_FALLBACK=true. Vault health and tenant DEK availability are not probed.

Environment checks inspect production dotenv files and the scanner process environment locally. Evidence contains setting names and fixed descriptions only. Values are never included in reports.

## Remediation

Set TENANT_DATA_ENCRYPTION_FALLBACK_KEY (or TENANT_DATA_ENCRYPTION_KEY) to a unique random value of at least 32 characters, distinct from signing secrets. Back it up securely and verify Vault/KMS separately.

See [deployment checks](../deployment.md) for precedence, Railway, GitHub Actions, and rule selection.
