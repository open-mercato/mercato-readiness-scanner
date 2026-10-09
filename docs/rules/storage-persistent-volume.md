# Local storage is placed on persistent media

**Rule ID:** `storage-persistent-volume`
**Severity:** High

Container filesystems are usually ephemeral. Uploads and documents must live on
a persistent volume or durable object storage and must be included in recovery
planning. A static scan cannot prove provider durability.

## Remediation

Map every storage-owning path to a durable volume or supported object store.
Test upload, download, deletion, quota, restart persistence, backup, and restore
behavior in the deployed topology.

See [Storage Hub](https://docs.openmercato.com/user-guide/storage-hub).
