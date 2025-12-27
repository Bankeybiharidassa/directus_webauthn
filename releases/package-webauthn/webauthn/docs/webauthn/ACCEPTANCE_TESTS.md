# file: docs/webauthn/ACCEPTANCE_TESTS.md
# purpose: acceptance checklist for WebAuthn registration, login, and dry-test (DEV/PROD)
# version: 1.2.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: DEV
# last_reviewed_by: codex
# last_reviewed_at: 2025-12-17T00:00:00Z

## Prerequisites

- Export `env file` (DEV mode uses `<ENV_FILE_PATH>`) and set `WEBAUTHN_MODE=dev` for verbose logging; PROD uses `<ENV_FILE_PATH>` and must keep logging minimal.
- Verify tokens first:
  ```bash
  curl -sS -H "Authorization: Bearer $DIRECTUS_TOKEN_DEV" <DIRECTUS_BASE_URL>/users/me | jq '.data.id'
  ```
- Ensure `jq` and `curl` are installed. Browser steps require WebAuthn-capable Chromium/Firefox/WebKit.

## Helper script (DEV)

- `tools/webauthn/diagnose-passkeys-dev.sh --mode dev --email <user@example.com> --token "$DIRECTUS_TOKEN_DEV"`
  - Checks `/webauthn/` health, `/registration/options`, `/authentication/options`, `/drytest/options`, `/credentials`, and DEV-only `/debug/credentials` with safe summaries.

## Curl checks (DEV)

```bash
MODE=dev
BASE=${DIRECTUS_URL_DEV:-<DIRECTUS_BASE_URL>}
TOKEN=${DIRECTUS_TOKEN_DEV:?set DIRECTUS_TOKEN_DEV}
EMAIL="user@example.com"

# Registration options (rp + user required)
curl -sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "$BASE/webauthn/registration/options" -d "{}" | jq '.publicKey.rp, .publicKey.user.id'

# Authentication options (rpId + challenge required)
curl -sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "$BASE/webauthn/authentication/options" -d "{}" | jq '.publicKey.rpId, .publicKey.challenge'

# Dry-test options (rpId + challenge)
curl -sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "$BASE/webauthn/drytest/options" | jq '.publicKey.rpId, .publicKey.challenge, .dryTestAttemptId'

# Credential listing (metadata only)
curl -sS -H "Authorization: Bearer $TOKEN" "$BASE/webauthn/credentials" | jq '.credentials | length'

# DEV-only diagnostic counts
curl -sS -H "Authorization: Bearer $TOKEN" "$BASE/webauthn/debug/credentials" | jq '.me_id, .total_credentials_count, .my_credentials_count, .sample'
```

## Manual browser checklist (DEV)

1. **Login with password** (session cookie set).
2. Profile → **Add passkey**
   - `/registration/options` returns `publicKey.rp` + `user.id`.
   - Browser prompt succeeds; `/registration/verify` returns tokens and the credential appears in `/webauthn/credentials`.
3. Profile shows passkeys
   - List is sourced from `/webauthn/credentials` and displays `nickname`, `created_at`, `transports`/`aaguid` when present.
4. Profile → **Dry-test passkey**
   - `/drytest/options` returns `rpId` + `challenge` + `dryTestAttemptId`.
   - `/drytest/verify` returns `{ ok:true, belongsToUser:true, credential_id, credential_name, deviceType, transports, storedCounter, newCounter }`.
   - UI shows “Used key: <nickname> (<type>)” and does not change session state.
5. **Logout**, then **Login with passkey**
   - `/authentication/options` returns `rpId` + `challenge`; browser prompt succeeds.
   - `/authentication/verify` sets Directus session (check `/users/me` succeeds with the same cookie jar).

## PROD expectations

- Same functional flow as DEV; logging is minimal (no credential payloads, build fingerprint omitted).
- `/webauthn/debug/credentials` must return 404 in PROD.

## Failure handling

- Missing `publicKey`, `rp`, or `rpId` must fail fast client-side (React guard) and server-side (DEV guard returns `INVALID_WEBAUTHN_OPTIONS`).
- Dry-test failures must return `{ ok:false, credential_id?, error, storedCounter?, newCounter? }` instead of 500s.
