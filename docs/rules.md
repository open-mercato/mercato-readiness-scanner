# Rule catalog

All rules default to enabled. Use `--only` and `--ignore` to select rules; disabled checks remain `skipped` in schema version 1 reports. See [deployment checks](deployment.md).

| ID | Severity | Best practice |
|---|---|---|
| [secrets-live-env-untracked](rules/secrets-live-env-untracked.md) | critical | Live environment files are not tracked |
| [secrets-no-tracked-credentials](rules/secrets-no-tracked-credentials.md) | critical | Credential and private-key files are not tracked |
| [secrets-ignore-policy](rules/secrets-ignore-policy.md) | high | Sensitive local files are ignored |
| [runtime-env-template](rules/runtime-env-template.md) | high | Production configuration has a sanitized template |
| [runtime-production-scripts](rules/runtime-production-scripts.md) | high | Production build and start scripts are explicit |
| [edge-tls-and-canonical-origin](rules/edge-tls-and-canonical-origin.md) | critical | TLS and canonical origin are verified at deployment |
| [edge-trusted-proxy-depth](rules/edge-trusted-proxy-depth.md) | high | Trusted proxy depth is topology-specific |
| [edge-allowed-origins](rules/edge-allowed-origins.md) | high | Browser and real-time origins are restricted |
| [edge-security-headers](rules/edge-security-headers.md) | high | Application security headers are configured |
| [operations-health-check](rules/operations-health-check.md) | high | A deployment health check is wired |
| [infrastructure-private-services](rules/infrastructure-private-services.md) | critical | Stateful services are not publicly published |
| [container-non-root-user](rules/container-non-root-user.md) | high | Production containers run as non-root |
| [supply-chain-immutable-install](rules/supply-chain-immutable-install.md) | high | Deployments use immutable dependency installation |
| [supply-chain-single-lockfile](rules/supply-chain-single-lockfile.md) | medium | Exactly one package lockfile is committed |
| [infrastructure-shared-redis](rules/infrastructure-shared-redis.md) | high | Multi-process deployments use shared Redis coordination |
| [release-database-migrations](rules/release-database-migrations.md) | high | Database migrations are part of release startup |
| [release-immutable-artifact](rules/release-immutable-artifact.md) | high | Production deploys select an immutable artifact |
| [release-validation-gate](rules/release-validation-gate.md) | high | Release validation gates the exact revision |
| [operations-worker-topology](rules/operations-worker-topology.md) | high | Background workers have an explicit process topology |
| [workers-release-parity](rules/workers-release-parity.md) | high | Web and worker processes use the same release artifact |
| [storage-persistent-volume](rules/storage-persistent-volume.md) | high | Local storage is placed on persistent media |
| [data-backup-restore-runbook](rules/data-backup-restore-runbook.md) | critical | Backups and restore rehearsal are documented |
| [release-rollback-runbook](rules/release-rollback-runbook.md) | high | Rollback and forward-fix procedures are documented |
| [observability-telemetry-pipeline](rules/observability-telemetry-pipeline.md) | medium | Logs and telemetry have a production pipeline |
| [runtime-supported-node](rules/runtime-supported-node.md) | medium | The app pins a supported Node.js runtime |
| [runtime-debug-features-disabled](rules/runtime-debug-features-disabled.md) | high | Development-only features default off |
| [secrets-jwt-signing](rules/secrets-jwt-signing.md) | critical | Signing secrets resist known weak defaults |
| [data-tenant-encryption-enabled](rules/data-tenant-encryption-enabled.md) | critical | Tenant database field encryption is enabled |
| [data-encryption-key-config](rules/data-encryption-key-config.md) | critical | Encryption has an independent fallback key |
| [services-postgres-credentials](rules/services-postgres-credentials.md) | critical | PostgreSQL uses explicit non-default credentials |
| [services-redis-credentials](rules/services-redis-credentials.md) | high | Redis connections require authentication |
| [services-other-credentials](rules/services-other-credentials.md) | high | Supporting services avoid default credentials |
| [runtime-production-environment](rules/runtime-production-environment.md) | high | Effective environment targets production |
| [runtime-tracing-disabled](rules/runtime-tracing-disabled.md) | high | Tracing and debug switches are disabled |
| [permissions-env-files](rules/permissions-env-files.md) | high | Production environment files have private permissions |
| [permissions-upload-directories](rules/permissions-upload-directories.md) | high | Private upload storage has restricted permissions |
