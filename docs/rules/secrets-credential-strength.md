# Credentials reject weak values and published defaults

**Rule ID:** `secrets-credential-strength`
**Severity:** Critical

This check runs by default in every scan starting with version 0.2.1.
The old `--check-secrets` flag remains accepted for compatibility. The check examines credential-like names in root `.env`,
`.env.production`, `.env.local`, `.env.production.local`, the scanner's visible
runtime environment, and supported Compose service environments. It also inspects
Redis `--requirepass` settings. Application code, shell commands, and dotenv
expansions are never executed. Every supplied production file is inspected;
a strong runtime override does not hide a weak value left in a file.

Detected values include JWT and session signing secrets, database and other
service passwords, API keys/tokens, webhooks, and recognized credential fields in
JSON objects. Database/service URLs, URL query and fragment credential fields,
percent-encoded passwords, and password-bearing connection strings are inspected.
Names ending in metadata such as `_FILE`, `_ID`, or `_TTL`, public/publishable
keys, token limits, and feature toggles are excluded from strength assessment.

Failures include known defaults, placeholders, credentials copied from sanitized
templates (even if they look strong), empty signing or database passwords, short values, repeated
patterns, and predictable sequences. Signing keys need at least 32 bytes of key
material; passwords need at least 16 characters; other detected opaque secrets
need at least 16 bytes. Hex/base64 key encodings are assessed as decoded material
when recognized. These are scanner heuristics, not proof of cryptographic entropy.

Unresolved references, password-free service URLs, unsupported credential objects,
embedded private keys, and opaque JWTs need operator verification. Unsigned JWTs
fail; other JWT signatures, issuers, audiences, and expiry are not verified.
Blank optional integration values are ignored. Missing signing/database settings
or uninspectable files generate a coverage warning, not a pass.

Only validated variable names, fixed reasons, and known relative source labels
enter findings. Values, hashes, lengths, URLs, parser error text, and home paths
are never emitted by this check. Private-key files, secret stores, external
Compose `env_file` paths, and arbitrary files are not opened. File reads are
bounded to 1 MiB and refuse symbolic links, hard links, and non-regular files.

## Remediation

Generate independent production credentials with a cryptographically secure
generator. Rotate exposed values and replace every copied template/default.
Inject values through the deployment secret mechanism rather than shipping a
plaintext `.env` file. Verify provider-specific policies, credentials outside
the supported sources, and deployed authentication separately. `apply` leaves
credential changes to an operator.

The framework's [JWT policy](https://github.com/open-mercato/open-mercato/blob/main/packages/shared/src/lib/auth/jwt.ts)
rejects missing, placeholder, and short signing secrets in production.
