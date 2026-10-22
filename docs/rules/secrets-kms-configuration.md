# KMS configuration and key custody are verified

**Rule ID:** `secrets-kms-configuration`
**Severity:** High

This rule produces a warning when no complete Open Mercato Vault KMS
configuration can be identified, and when live credential inspection is disabled.
During a scan, `VAULT_ADDR` must be an HTTP(S) URL and `VAULT_TOKEN` must
be nonempty and not an obvious placeholder or unresolved reference to recognize
configured Vault settings. Settings in Compose are considered per service;
dotenv layers and the visible runtime environment are considered together.

Configured settings still produce a review warning: the scanner does not contact
Vault, authenticate, read its keys, verify IAM/policies, or prove recovery.
KMS presence does not exempt weak configured fallback keys from the separate
critical encryption-key check. Generic cloud KMS variable names alone do not
prove the application uses a supported KMS implementation.

## Remediation

Configure Open Mercato's Vault KMS with `VAULT_ADDR` and `VAULT_TOKEN` using your
deployment secret mechanism. Verify access policies, durable key storage,
backup/recovery, rotation, and the application's actual encryption behavior.

Without KMS, deploy strong, durable encryption keys through Railway or Cloudflare
secrets, a secret manager, or inject GitHub Actions secrets during deployment.
Do not ship production encryption keys in a plaintext `.env` file. Keep recovery
copies under restricted access. A hosting secret mechanism or CI secret is a
delivery mechanism; it does not provide KMS encryption/rotation capabilities by
itself. Avoid putting secrets in logs, command-line arguments, or built images.
