# WebAuthn Storage Contract

This extension uses two Directus collections only:

- `webauthn_credentials` — stores registered credential metadata and counters
- `webauthn_challenges` — stores issued challenges and their verification state

> Any other collection names are treated as drift and ignored.

## Required fields

### `webauthn_credentials`

- `id` (primary key managed by Directus; integer or UUID are both valid)
- `user` (M2O to `directus_users.id`, required)
- `credential_id` (string, unique, base64url)
- `public_key` (text/string)
- `sign_count` (integer, default 0)
- `transports` (json, nullable)
- `aaguid` (uuid, nullable)
- `device_type` (string, nullable)
- `backed_up` (boolean, nullable)
- `nickname` (string, nullable)
- `user_agent` (text, nullable)
- `origin` (string, nullable)
- `created_at`, `updated_at`, `last_used_at` (datetime, last_used_at nullable)

### `webauthn_challenges`

- `id` (primary key managed by Directus; integer or UUID are both valid)
- `user` (M2O to `directus_users.id`, nullable)
- `challenge` (string; stored JSON payload)
- `type` (string: `registration` or `authentication`)
- `expires_at`, `created_at` (datetime)
- `used_at` (datetime, nullable)
- `rp_id` (string, nullable)
- `origin` (string, nullable)

### Primary key rules

- Primary keys may remain integer or UUID. The API never writes `id` manually; challenge correlation uses `challenge_id` and
  credentials rely on `credential_id`.
- Schema fixes must be applied through Directus collections/fields/relations routes only—no `/utils/sql` or database-level
  migrations.

## Schema version marker

The extension currently targets **schema version 1**. The health endpoint reports `expected_schema_version` and the schema version it found.

## Provisioning

- Runtime handlers call `ensureWebauthnStorage()` to validate collections/fields. Provisioning/repair is performed by
  Directus routes (`tools/provision_webauthn_collection.py`) and never by direct SQL.

## Error surface

If the schema is missing or incomplete, endpoints return `webauthn_storage_schema_invalid` with diagnostics. If the schema
exists but the primary key type is incorrect, endpoints return `webauthn_storage_schema_mismatch` with mismatched details.

- `directus_url`
- `collections_checked`
- `missing_collections`
- `missing_fields_by_collection`
- `mismatched_fields`
- `expected_schema_version`

Use the provisioning tool or fix schema drift before retrying.
