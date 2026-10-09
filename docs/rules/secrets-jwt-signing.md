# Signing secrets resist known weak defaults

**Rule ID:** `secrets-jwt-signing`
**Severity:** Critical

Requires JWT_SECRET and checks non-empty optional AUTH_SECRET, NEXTAUTH_SECRET, and audience/collaboration JWT overrides. Rejects values shorter than 32 characters, known example placeholders, unresolved substitutions, and values with fewer than eight distinct characters. This is a heuristic policy, not an entropy proof. Empty optional overrides are treated as unused.

Environment checks inspect production dotenv files and the scanner process environment locally. Evidence contains setting names and fixed descriptions only. Values are never included in reports.

## Remediation

Set JWT_SECRET to a unique random value of at least 32 characters. Set optional signing-secret overrides to equally strong independent values.

See [deployment checks](../deployment.md) for precedence, Railway, GitHub Actions, and rule selection.
