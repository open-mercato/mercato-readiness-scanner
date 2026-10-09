# Private upload storage has restricted permissions

**Rule ID:** `permissions-upload-directories`
**Severity:** High

Inspects metadata under uploads, storage, public/uploads, var/uploads, and configured ATTACHMENTS_STORAGE_ROOT, ATTACHMENTS_PARTITION_*_ROOT, UPLOADS_DIR, STORAGE_PATH, or ATTACHMENTS_STORAGE_PATH mounts. Rejects world access, executable upload files, missing owner-read access, or missing owner-write/traverse access on directories. Traversal stops at 5,000 entries or depth 12 and never follows symlinks. Missing, unreadable, or incomplete trees require review. This is a private-uploads policy; deliberately public assets can use an explicit rule exception. No upload contents are opened, and actual write access, ownership, ACLs, and remote object-storage policies need separate verification.

Environment checks inspect production dotenv files and the scanner process environment locally. Evidence contains setting names and fixed descriptions only. Values are never included in reports.

## Remediation

Give the app owner read/write/traverse access to private storage, remove world access, and keep uploaded files non-executable. Use 0700/0750 directories and 0600/0640 files; verify volume ownership and remote storage separately.

See [deployment checks](../deployment.md) for precedence, Railway, GitHub Actions, and rule selection.
