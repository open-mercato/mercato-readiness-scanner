# Tracing and debug switches are disabled

**Rule ID:** `runtime-tracing-disabled`
**Severity:** High

Rejects enabled debug, SQL logging, trace, profiling, autologin, and test-injection switches. Requires a disabled/noop telemetry backend and disables explicitly configured OTEL trace exporters unless OTEL_SDK_DISABLED=true. An unset backend is treated as the framework noop default. Applications intentionally using tracing may explicitly ignore this policy; tracing code is never imported or executed.

Environment checks inspect production dotenv files and the scanner process environment locally. Evidence contains setting names and fixed descriptions only. Values are never included in reports.

## Remediation

Disable debug, SQL logging, profiling, autologin, test injection, and tracing flags. Use TELEMETRY_BACKEND=noop and OTEL_TRACES_EXPORTER=none (or OTEL_SDK_DISABLED=true).

See [deployment checks](../deployment.md) for precedence, Railway, GitHub Actions, and rule selection.
