# Deployment checks

Run the scanner from your Open Mercato app with Node.js 24+. A local checkout provides repository evidence. A command inside the production container also sees its inherited environment and mounted storage.

## Effective environment

Values take precedence in this order, including an explicitly empty higher-priority value:

1. Relevant environment variables inherited by the scanner process.
2. `.env.production.local`.
3. `.env.local`.
4. `.env.production`.
5. `.env`.

The scanner inspects this production configuration even when launched from a development shell. `.env.example`, `.env.sample`, and `.env.template` do not supply deployed secrets. Only the four fixed production dotenv paths are opened for value inspection; files over 1 MiB, symlinks, directories, and files escaping the application root are rejected. An existing unreadable file produces a finding.

Dotenv supports quoted values, comments, `export`, and variable references (`$NAME`, `${NAME}`, `${NAME:-default}`). Inherited process values remain literal. Unresolved references and cycles need review. No shell commands, JavaScript configuration, target application scripts, or dotenv plugins are executed. The scanner does not mutate `process.env`.

Secret checks reject missing required settings, known development placeholders, insufficient length, obvious repetition, and unresolved substitutions. These policies do not prove cryptographic entropy or successful authentication. Values, URLs containing credentials, and configured absolute storage paths are never copied into evidence. Private-key files, token caches, and external secret stores are not opened.

## Railway

Inside the service's deployed container, change to the app root and run:

```bash
npx --yes @open-mercato/readiness-scanner@0.1.0 scan . --fail-on high
```

The scanner inherits Railway's injected service variables, including reference variables already resolved by Railway. It does not need a local `.env` file. Configure `ATTACHMENTS_STORAGE_ROOT` (the framework setting), partition-specific `ATTACHMENTS_PARTITION_*_ROOT` overrides, or the scanner aliases `UPLOADS_DIR`, `STORAGE_PATH`, and `ATTACHMENTS_STORAGE_PATH` if private uploads live on a mounted path outside the app root. Storage checks use metadata only and never follow symlinks.

You can enter the deployed container with [Railway SSH](https://docs.railway.com/cli/ssh). A scan in a local shell can inspect injected variable values but checks the local filesystem; use the actual deployed container for mounted-volume permissions.

For a [Railway pre-deploy command](https://docs.railway.com/deployments/pre-deploy-command), use the same pinned scanner command. Prefer installing the package in the image ahead of time if the command must run without npm access:

```bash
mercato-readiness scan . --fail-on high
```

The image must retain `package.json` and `src/modules.ts` for application detection. Railway pre-deploy containers do not mount service volumes; run upload-permission checks inside the running service when a volume is needed. Missing storage produces operator-review warnings. A failed scanner command stops a pre-deploy gate; warnings do not.

## GitHub Actions

Place this workflow in the **application repository**. Configure the production environment's GitHub secrets and variables to match the deployment. Run a deployment step only after this job succeeds. Values passed below are names and GitHub expressions, not sample credentials.

```yaml
name: Production readiness
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  readiness:
    runs-on: ubuntu-latest
    environment: production
    env:
      NODE_ENV: production
      APP_URL: ${{ vars.APP_URL }}
      APP_ALLOWED_ORIGINS: ${{ vars.APP_ALLOWED_ORIGINS }}
      RATE_LIMIT_TRUST_PROXY_DEPTH: ${{ vars.RATE_LIMIT_TRUST_PROXY_DEPTH }}
      JWT_SECRET: ${{ secrets.JWT_SECRET }}
      DATABASE_URL: ${{ secrets.DATABASE_URL }}
      REDIS_URL: ${{ secrets.REDIS_URL }}
      TENANT_DATA_ENCRYPTION: 'yes'
      TENANT_DATA_ENCRYPTION_FALLBACK_KEY: ${{ secrets.TENANT_DATA_ENCRYPTION_FALLBACK_KEY }}
      TELEMETRY_BACKEND: noop
      OTEL_TRACES_EXPORTER: none
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-node@v6
        with:
          node-version: 24
      - name: Check production configuration
        run: >-
          npx --yes @open-mercato/readiness-scanner@0.1.0 scan .
          --fail-on high
          --markdown "$RUNNER_TEMP/readiness.md"
          --json "$RUNNER_TEMP/readiness.json"
```

Also pass enabled-service settings such as `MEILISEARCH_HOST` and `MEILISEARCH_API_KEY`, optional JWT signing overrides, and additional Redis role URLs. The example's policy disables tracing; do not hard-code a safe value in CI if the deployed value differs—map the real setting instead. GitHub secrets absent from the environment arrive as empty values and fail required checks.

This checks the job's checkout, files, and supplied environment. It does not remotely inspect Railway or verify that GitHub secrets equal Railway variables. To inspect actual deployment settings, execute the scanner inside that deployment. Reports remain local; this workflow does not upload them.

## Rule selection

```bash
mercato-readiness --list-rules
mercato-readiness scan . --ignore runtime-tracing-disabled --fail-on high
mercato-readiness scan . --only secrets-jwt-signing,services-postgres-credentials --fail-on critical
```

Both selection flags are repeatable and accept comma-separated IDs. `--only` limits execution to its union of IDs; `--ignore` then removes IDs from that set. Disabled rules are reported as `skipped` with a fixed reason and do not fail the gate. Unknown IDs exit 2. Record an exception's reason in your deployment policy. Every rule defaults to enabled.

## Output and exit codes

Reports are saved before the severity threshold is applied. `--markdown` and `--json` add files while retaining terminal stdout. `--output` selects one destination and suppresses stdout for files; `.md`/`.json` infer the format. Files are written atomically with mode 0600. The scanner only writes explicitly requested reports.

| Code | Meaning |
|---|---|
| 0 | Scan succeeded and no failed finding meets the threshold |
| 1 | A failed finding meets `--fail-on critical`, `high`, `medium`, or `low` |
| 2 | Invalid CLI usage, unknown rule ID, or unrecognized app |
| 3 | Unexpected scanner or report-writing failure |

The default threshold is `never`. Warnings always require operator review and do not count as failed findings. A pass establishes only the configuration or metadata described by that rule. Live service credentials, TLS, KMS availability, encrypted database records, provider disk encryption, ACLs, ownership, alerts, and restore rehearsal require separate operational verification.
