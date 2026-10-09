# Production environment files have private permissions

**Rule ID:** `permissions-env-files`
**Severity:** High

Uses lstat metadata on the four allowlisted production dotenv files. Files must be owner-readable, have no group/world access, and be regular files rather than directories or symlinks. No local file is required on a platform using process variables. POSIX modes do not prove ownership, ACLs, parent-directory protection, or secret-store access policy.

Environment checks inspect production dotenv files and the scanner process environment locally. Evidence contains setting names and fixed descriptions only. Values are never included in reports.

## Remediation

Use owner-only permissions (0600 or 0400) for environment files and keep them out of Git. On Windows, verify ACLs separately.

See [deployment checks](../deployment.md) for precedence, Railway, GitHub Actions, and rule selection.
