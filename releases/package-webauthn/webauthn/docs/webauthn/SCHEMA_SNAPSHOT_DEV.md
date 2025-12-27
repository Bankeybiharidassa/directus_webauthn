# file: docs/webauthn/SCHEMA_SNAPSHOT_DEV.md
# purpose: summarize the latest DEV Directus schema relevant to WebAuthn/passkeys
# version: 1.1.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: DEV
# last_reviewed_by: codex
# last_reviewed_at: 2026-03-01T03:00:00Z

## Snapshot source

- Pulled from `<DIRECTUS_BASE_URL>` using `DIRECTUS_TOKEN_DEV` from `<ENV_FILE_PATH>` on 2025-12-17 via `/collections`, `/fields/{collection}`, and `/relations`.
- Raw export stored at `docs/webauthn/SCHEMA_SNAPSHOT_DEV.json` (64 collections, 73 relations).

## WebAuthn collections

### `webauthn_credentials`

- **Required columns:** `id` (uuid PK), `credential_id` (varchar), `public_key` (text), `sign_count` (integer), `user` (uuid → `directus_users.id`), `created_at` (timestamptz).
- **Optional columns:** `nickname`, `last_used_at`, `origin`, `user_agent`, `transports` (json), `aaguid`.
- **Not present:** `name`, `type`, or other label fields. UI must rely on `nickname` + metadata.
- **Implications:**
  - Backend must always persist `user`, `credential_id`, `public_key`, and `sign_count`; missing any of these will violate schema constraints and break listings.
  - ReactApp listing must not filter on absent fields (e.g., `name`, `type`) and should display `nickname` as the human label.
  - `transports` is `json`, so insert/update should keep it an array when provided.

### Relations

- `webauthn_credentials.user` → `directus_users.id` (m2o, required).

## Directus user security fields

- `directus_users.passkey_only_login` (boolean, default `false`).
  - ReactApp2 uses this flag to block password login attempts and to render the account-level passkey-only toggle.

## How to refresh

```bash
set -a && source env file && set +a
python - <<'PY'
import os, json, requests
base = osenv fileiron["DIRECTUS_URL_DEV"]
token = osenv fileiron["DIRECTUS_TOKEN_DEV"]
headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

def get(path):
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    return requests.get(url, headers=headers, timeout=30).json().get("data", [])

collections = {}
for col in get('/collections'):
    name = col.get('collection')
    fields = {f.get('field'): f for f in get(f"/fields/{name}") if f.get('field')}
    collections[name] = {"info": {"collection": name, "meta": col.get('meta'), "schema": col.get('schema')}, "fields": fields}

snapshot = {"collections": collections, "relations": get('/relations')}
with open('docs/webauthn/SCHEMA_SNAPSHOT_DEV.json', 'w') as fh:
    json.dump(snapshot, fh, indent=2, sort_keys=True)
print('ok')
PY
```

## Quick validation checklist (DEV)

- `webauthn_credentials` contains all required columns listed above.
- `transports` and `aaguid` exist with `json` / `character varying` data types respectively.
- Relation `webauthn_credentials.user` targets `directus_users.id` and is required.
- `directus_users.passkey_only_login` exists and is readable by ReactApp2.
