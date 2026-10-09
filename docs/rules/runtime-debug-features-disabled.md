# Development-only features default off

**Rule ID:** `runtime-debug-features-disabled`
**Severity:** High

Debugging, profiling, autologin, test injection, and browser DevTools switches
can reveal data or weaken controls when enabled in production. This rule checks only allowlisted boolean template defaults, so a safe template
remains an operator-verification result. The separate
[runtime-tracing-disabled](runtime-tracing-disabled.md) rule inspects effective
production environment settings locally without reporting their values.

## Remediation

Make every development-only switch false or empty in the sanitized template and
the production secret store. Verify the deployed application has no demo login,
test injection, verbose query output, or emergency bypass enabled.

See [Prepare the production environment and secrets](https://docs.openmercato.com/deployment/production-readiness#ordered-production-checklist).
