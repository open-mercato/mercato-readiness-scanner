# Production secrets are injected through a secret mechanism

**Rule ID:** `secrets-deployment-injection`
**Severity:** High

This rule always requires operator verification. It reports known local
production dotenv paths without opening them during a default scan. A local
`.env` file is not proof that production ships secrets, and absence of one is
not proof of secure deployment.

## Remediation

Keep production credentials and encryption keys out of deployed plaintext
`.env` files, source control, container layers, build artifacts, logs, and
command-line arguments. Use your hosting platform's secret mechanism, such as
Railway or Cloudflare secrets, or a dedicated secret manager. GitHub Actions
secrets can supply values during deployment; inject them into the destination's
runtime secret mechanism rather than persisting them in an artifact.

Review provider access controls, deployment logs, artifact contents, rotation,
and recovery. Preserve encryption keys securely to avoid losing access to
encrypted data. Secret delivery and KMS key-management capabilities are separate
operational concerns. The scanner performs no remote deployment inspection.
