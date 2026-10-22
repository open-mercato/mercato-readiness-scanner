# Encryption keys reject weak fallbacks and development defaults

**Rule ID:** `secrets-encryption-key-strength`
**Severity:** Critical

Live-value inspection runs by default during scan starting with version 0.2.1.
This check covers
`TENANT_DATA_ENCRYPTION_FALLBACK_KEY`, `TENANT_DATA_ENCRYPTION_KEY`,
`KMS_MASTER_KEY`, `FORMS_ENCRYPTION_MASTER_KEY`, `LOOKUP_HASH_PEPPER`, and detected
encryption-key settings in the supported local production sources.

Keys fail when they use public development defaults, placeholders, copied
template material, fewer than 32 bytes of recognized key material, repeated or
low-diversity patterns, or predictable sequences. Unsafe `${NAME:-default}`
fallbacks also fail. `ALLOW_DERIVED_KMS_FALLBACK` enabled without an explicit
tenant key fails because it permits the published development key outside
production. Explicitly disabling tenant encryption also fails.

Strong-looking local keys can satisfy this static policy without proving their
randomness, custody, backup, deployment, or use. Missing or unresolved key
material requires verification. No keys are generated, written, rotated,
exported, or sent to an agent by this check.

## Remediation

Use durable, independently generated encryption roots with at least 32 random
bytes. Configure KMS where possible. Otherwise inject keys through Railway or
Cloudflare secrets, a secret manager, or GitHub Actions secrets during deployment.
Keep them out of plaintext `.env` release artifacts.

Preserve existing keys securely. Replacing a key without a migration can make
stored data unreadable; plan and rehearse key rotation and recovery separately.

See the framework's [KMS implementation](https://github.com/open-mercato/open-mercato/blob/main/packages/shared/src/lib/encryption/kms.ts)
for tenant fallback precedence and the development default.
