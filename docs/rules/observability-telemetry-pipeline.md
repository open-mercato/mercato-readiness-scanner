# Logs and telemetry have a production pipeline

**Rule ID:** `observability-telemetry-pipeline`
**Severity:** Medium

Production incidents require centralized structured logs and useful metrics or
traces with retention, access control, redaction, dashboards, and owned alerts.
Configuration presence still requires live verification.

## Remediation

Connect application and worker logs plus OTLP/APM telemetry to an operated
backend. Verify ingestion, sensitive-data filtering, retention, alert delivery,
and first-response runbooks using a controlled test signal.

See [OTLP telemetry](https://docs.openmercato.com/framework/runtime/telemetry).
