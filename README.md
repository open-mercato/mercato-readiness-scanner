# Open Mercato Readiness Scanner

A read-only TypeScript CLI that inspects an application created with
[`create-mercato-app`](https://www.npmjs.com/package/create-mercato-app) and reports
production-readiness gaps with security-scanner-style results.

> This repository is private and the package is **not published to npm**. Run it
> from a trusted local checkout until the project is intentionally released.

## Quick start

Node.js 24 or newer is required.

```bash
npm ci
npm run build
node dist/cli.js scan /path/to/open-mercato-app
```

The default terminal report groups failed, review-only, skipped, and passing
checks with `❌`, `⚠️`, `⏭️`, and `✅` markers. Every actionable result includes
remediation text and a permanent rule-documentation URL.

## Save a report

Keep the formatted terminal report on screen while writing both portable
formats:

```bash
node dist/cli.js scan . --markdown readiness.md --json readiness.json
```

Or select a single standard-output format and optionally save it:

```bash
node dist/cli.js scan . --format markdown --output readiness.md
node dist/cli.js scan . --format json --output readiness.json
```

Use `--fail-on high` (or `critical`, `medium`, or `low`) in CI to return exit
code 1 when a failed rule meets the chosen severity. The default, `never`,
always returns 0 after a successful scan. Invalid usage or an invalid target
returns 2.

## What the scanner does

The scanner recognizes a generated Open Mercato app by its
`@open-mercato/core` dependency and `src/modules.ts`. It examines only bounded,
local configuration and documentation surfaces. It never runs target scripts,
loads the application, contacts its services, or performs network probes.

Live `.env*` files are never opened. Git is queried only for tracked path names
so the scanner can report a committed live environment file without reading its
contents. Only the explicitly sanitized `.env.example`, `.env.sample`, and
`.env.template` forms are eligible for configuration-name checks. Evidence omits
absolute paths and configuration values.

Static evidence cannot prove live TLS, backups, restores, alerts, or provider
settings. Those checks intentionally return `⚠️ review` when configuration or a
runbook exists but an operator still needs to verify the deployed environment.

## Rule catalog

Each best practice has a stable ID and its own documentation URL. Rule IDs are
also stable machine keys in the JSON report.

| Severity | Best practice |
|---|---|
| Critical | [Live environment files are not tracked](docs/rules/secrets-live-env-untracked.md) |
| High | [Sensitive local files are ignored](docs/rules/secrets-ignore-policy.md) |
| High | [Production configuration has a sanitized template](docs/rules/runtime-env-template.md) |
| High | [Production build and start scripts are explicit](docs/rules/runtime-production-scripts.md) |
| Critical | [TLS and canonical origin are verified at deployment](docs/rules/edge-tls-and-canonical-origin.md) |
| High | [Trusted proxy depth is topology-specific](docs/rules/edge-trusted-proxy-depth.md) |
| High | [Browser and real-time origins are restricted](docs/rules/edge-allowed-origins.md) |
| High | [Application security headers are configured](docs/rules/edge-security-headers.md) |
| High | [A deployment health check is wired](docs/rules/operations-health-check.md) |
| High | [Production containers run as non-root](docs/rules/container-non-root-user.md) |
| High | [Deployments use immutable dependency installation](docs/rules/supply-chain-immutable-install.md) |
| Medium | [Exactly one package lockfile is committed](docs/rules/supply-chain-single-lockfile.md) |
| High | [Database migrations are part of release startup](docs/rules/release-database-migrations.md) |
| High | [Background workers have an explicit process topology](docs/rules/operations-worker-topology.md) |
| High | [Local storage is placed on persistent media](docs/rules/storage-persistent-volume.md) |
| Critical | [Backups and restore rehearsal are documented](docs/rules/data-backup-restore-runbook.md) |
| High | [Rollback and forward-fix procedures are documented](docs/rules/release-rollback-runbook.md) |
| Medium | [Logs and telemetry have a production pipeline](docs/rules/observability-telemetry-pipeline.md) |
| Medium | [The app pins a supported Node.js runtime](docs/rules/runtime-supported-node.md) |
| High | [Development-only features default off](docs/rules/runtime-debug-features-disabled.md) |

The overall operational baseline is the Open Mercato
[Production Readiness checklist](https://docs.openmercato.com/deployment/production-readiness).

## JSON contract

JSON output follows [`docs/report.schema.json`](docs/report.schema.json). It
contains the scanner version, scan timestamp, target directory name, aggregate
counts, and one result per rule. Consumers should key on `schemaVersion` and
`results[].id`, not display text.

## Development

```bash
npm run check
```

`npm run check` type-checks, runs the Node test suite, and builds the CLI. Do not
publish the package or make this repository public without explicit approval.
