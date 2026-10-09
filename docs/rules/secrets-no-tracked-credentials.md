# Credential and private-key files are not tracked

**Rule ID:** `secrets-no-tracked-credentials`
**Severity:** Critical

Private keys, token-bearing npm or MCP configuration, and secret-manager exports
must never enter version control. The scanner examines tracked path names only;
it never opens or reports the content of a matching file.

## Remediation

Remove the path from version control and history as appropriate, revoke or
rotate the affected material, and move it to an access-controlled secret store.
Use a narrow documented waiver for an intentionally public certificate rather
than weakening the global rule.

See [Prepare the production environment and secrets](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
