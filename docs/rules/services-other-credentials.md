# Supporting services avoid default credentials

**Rule ID:** `services-other-credentials`
**Severity:** High

Checks configured Vault, Meilisearch, OpenSearch, Elasticsearch, RabbitMQ, SMTP, MinIO, S3, and AWS credential surfaces for weak defaults and missing companion credentials. Recognizes explicit AWS role/workload-identity settings without opening identity token files. Recognizes the framework OM_INTEGRATION_STORAGE_S3_ACCESS_KEY_ID and OM_INTEGRATION_STORAGE_S3_SECRET_ACCESS_KEY preset, plus MEILISEARCH_HOST and MEILISEARCH_API_KEY. Credential requirements vary by provider; review workload identities and use --ignore with a documented rationale when this heuristic does not apply.

Environment checks inspect production dotenv files and the scanner process environment locally. Evidence contains setting names and fixed descriptions only. Values are never included in reports.

## Remediation

Set strong unique search, queue, SMTP, and object-storage credentials for enabled services. Prefer workload identities for AWS and verify service-side authentication separately.

See [deployment checks](../deployment.md) for precedence, Railway, GitHub Actions, and rule selection.
