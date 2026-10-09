# Backups and restore rehearsal are documented

**Rule ID:** `data-backup-restore-runbook`
**Severity:** Critical

A backup is useful only when all durable business data and required encryption
material can be restored within the agreed recovery objectives. Static runbook
text cannot prove that jobs or restores succeed.

## Remediation

Back up PostgreSQL and durable files, encrypt and separate copies, define
retention and ownership, monitor failures, and record a dated restore rehearsal
in an isolated environment. Confirm restored encrypted data is readable with
the recovered keys.

## Automatic fix

`mercato-readiness apply` can create a `docs/runbooks/backup-and-restore.md` stub when no
backup-and-restore runbook exists. The stub is a TODO checklist: it moves this rule to
⚠️ *review*, and only a named owner and a dated restore rehearsal can satisfy it.

See [Protect data and prove backups can be restored](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
