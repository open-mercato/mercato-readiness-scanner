# Development-only features default off

**Rule ID:** `runtime-debug-features-disabled`
**Severity:** High

Debugging, profiling, autologin, test injection, and browser DevTools switches
can reveal data or weaken controls when enabled in production. The scanner checks
only safe template defaults and never reads live environment values.

## Remediation

Make every development-only switch false or empty in the sanitized template and
the production secret store. Verify the deployed application has no demo login,
test injection, verbose query output, or emergency bypass enabled.

See [Prepare the production environment and secrets](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
