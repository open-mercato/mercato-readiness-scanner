<p align="center"><img src="https://raw.githubusercontent.com/open-mercato/mercato-readiness-scanner/main/.github/readme/open-mercato.svg" alt="Open Mercato logo" width="72" /></p>

<h1 align="center">Open Mercato Readiness Scanner</h1>

<p align="center"><strong>Check your app. Ship with confidence.</strong></p>

<p align="center">Check an Open Mercato app for production and security configuration gaps.<br />From your terminal, an AI agent, a Railway container, or a deployment pipeline.</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@open-mercato/readiness-scanner"><img src="https://img.shields.io/npm/v/@open-mercato/readiness-scanner?color=b4f372&amp;label=npm" alt="npm version" /></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/node-%E2%89%A524-1b1b1b" alt="Node.js 24 or newer" /></a>
  <a href="https://github.com/open-mercato/mercato-readiness-scanner/actions/workflows/ci.yml"><img src="https://github.com/open-mercato/mercato-readiness-scanner/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/open-mercato/mercato-readiness-scanner/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-bc9aff" alt="MIT license" /></a>
</p>

```bash
npx @open-mercato/readiness-scanner scan .
npx @open-mercato/readiness-scanner scan . --markdown readiness.md --json readiness.json
```

Your application is the scan target. The tool checks **repository configuration, production `.env` files, inherited environment variables, and local file permissions**, then reports actionable findings in the terminal, Markdown, and JSON. Secret values stay in memory and never appear in reports. Every finding has a stable rule ID, a remediation, and its own guide.

**Checking a deployment?** Run inside its container to inspect the actual environment and mounted storage. See [Railway and GitHub Actions](docs/deployment.md).

<p align="center"><a href="#quick-start">Quick start</a> · <a href="#save-reports-to-files">Save reports</a> · <a href="#delegate-to-an-ai-agent">AI agents</a> · <a href="docs/deployment.md">Deployment checks</a> · <a href="#choose-your-rules">Rule selection</a> · <a href="docs/rules.md">Rules</a> · <a href="https://docs.openmercato.com/">Docs</a> · <a href="https://discord.gg/f4qwPtJ3qA">Discord</a></p>

<p align="center"><img src="https://raw.githubusercontent.com/open-mercato/mercato-readiness-scanner/main/.github/readme/scan-flow.svg" alt="Inspect app configuration, production environment, and file permissions; run 36 readiness rules; save Markdown and JSON reports or gate deployment." width="100%" /></p>

## Quick start

You need **Node.js 24 or newer**. Run from an application created with `create-mercato-app`, or pass its path. The scanner needs no running services or application dependency installation.

### 1. Scan your application

```bash
cd my-app
npx @open-mercato/readiness-scanner scan .
```

Starting from a nested directory also works: the scanner locates the parent application using `@open-mercato/core` and `src/modules.ts`. You do not need to install or start the application to scan it.

### 2. Save your report

```bash
npx @open-mercato/readiness-scanner scan . \
  --markdown readiness.md \
  --json readiness.json
```

Both files are saved in the current directory while the terminal report stays visible. See [all file-output examples](#save-reports-to-files).

### 3. Add a deployment gate

```bash
npx @open-mercato/readiness-scanner scan . --fail-on high
```

This prints the report and exits with code 1 when a failed rule has high or critical severity. Use `critical`, `medium`, or `low` to change the threshold. The default is `never`. Warnings require operator review and do not fail this threshold.

See the complete [GitHub Actions and Railway examples](docs/deployment.md). Run inside the deployed container to inspect its actual environment and mounted storage. In GitHub Actions, explicitly pass the deployment settings through the job's `env` mapping.

## Save reports to files

Save a readable Markdown report:

```bash
npx @open-mercato/readiness-scanner scan . --markdown reports/readiness.md
```

Save a JSON report for automation:

```bash
npx @open-mercato/readiness-scanner scan . --json reports/readiness.json
```

Save both formats and fail a deployment gate on high or critical findings:

```bash
npx --yes @open-mercato/readiness-scanner@0.1.0 scan . \
  --markdown reports/readiness.md \
  --json reports/readiness.json \
  --fail-on high
```

Paths are relative to your current working directory. Parent directories are created automatically, existing destination files are replaced, and reports are written before the failure threshold is applied. `--markdown` and `--json` keep the terminal report visible. The terminal groups findings as failed (`❌`), review (`⚠️`), passed (`✅`), and skipped (`⏭️`).

For just one file without terminal output, use `--output reports/readiness.md` or `--output reports/readiness.json`; the extension selects the format. For JSON on stdout, use `--format json --output -`. Reports remain local unless you choose to share them.

## Delegate to an AI agent

Open your app in Codex, Claude Code, or another coding agent and give it this task:

```text
Check this Open Mercato application's production readiness.
From the app root, run:

npx --yes @open-mercato/readiness-scanner@0.1.0 scan . --markdown reports/readiness.md --json reports/readiness.json --fail-on high

Read both reports. Summarize failed findings and warnings by severity,
include their rule IDs, and propose concrete fixes with relevant file paths.
Explain which checks need verification inside the deployed container.
An exit code of 1 means findings crossed the threshold; still read the reports.
Keep the app unchanged, do not execute its scripts, and never print secrets
or upload the reports. Do not treat a static pass as proof of live service health.
```

The agent can review local source and configuration. To check Railway's actual environment and volume permissions, run the same command inside the deployed service; a local agent sees only its own process environment and filesystem.

## Choose your rules

```bash
# Discover rule IDs.
npx @open-mercato/readiness-scanner --list-rules

# Your deployment intentionally uses tracing.
npx @open-mercato/readiness-scanner scan . \
  --ignore runtime-tracing-disabled --fail-on high

# Check only signing secrets and database encryption.
npx @open-mercato/readiness-scanner scan . \
  --only secrets-jwt-signing,data-tenant-encryption-enabled,data-encryption-key-config \
  --fail-on high
```

`--ignore` and `--only` accept comma-separated IDs and can be repeated. Ignore takes precedence when the same ID appears in both. Disabled checks remain in the report as `skipped`. Unknown IDs return a usage error.

## What gets checked

The 36 documented rules cover signing secrets, environment defaults, tenant field encryption and its fallback key, PostgreSQL and Redis credentials, supporting services, private upload permissions, tracing and debug flags, TLS guidance, origins, headers, container users, supply chain, workers, migrations, backups, rollback, and observability.

Environment precedence is: inherited process variables, `.env.production.local`, `.env.local`, `.env.production`, then `.env`. Sanitized example files are checked as templates and never supply live credentials. Dotenv values are parsed as data; variable references can be expanded, and commands are never executed.

Checks are read-only. The scanner does not start the app, execute its scripts, log in to services, perform network probes, or upload reports. Local configuration cannot prove database authentication, encryption of existing records, provider disk encryption, live TLS, or backup recovery. Permission checks inspect bounded filesystem metadata without opening uploaded files.

## Install the CLI

For a persistent global command:

```bash
npm install --global @open-mercato/readiness-scanner
mercato-readiness scan . --fail-on high
```

The published package contains compiled JavaScript and TypeScript declarations and has no runtime dependencies. Its programmatic entry point exports `scan`, formatters, types, and the rule catalog.

## Documentation

| Topic | Guide |
|---|---|
| Railway, GitHub Actions, environment precedence, and exit codes | [Deployment checks](docs/deployment.md) |
| All rule IDs, severities, and remediation guides | [Rule catalog](docs/rules.md) |
| JSON report contract, schema version 1 | [Report schema](docs/report.schema.json) |
| Contribute, test, and release the CLI | [Development](docs/development.md) |

## Development

```bash
npm ci
npm run check
npm run test:standalone
```

All implementation, build helpers, lint configuration, and tests are TypeScript. GitHub CI runs lint/type checks, unit tests, builds, package checks, integration tests, and a fresh standalone-app scan on Node.js 24 and 26. The standalone test scaffolds `create-mercato-app@0.8.0`, installs the packed CLI into an isolated consumer, and validates its security reports without running application scripts.

---

Part of [Open Mercato](https://github.com/open-mercato/open-mercato). [Website](https://openmercato.com/) · [Framework docs](https://docs.openmercato.com/) · [Cloud](https://openmercatocloud.com/) · [Discord](https://discord.gg/f4qwPtJ3qA)

MIT © Open Mercato contributors. See [LICENSE](LICENSE).
