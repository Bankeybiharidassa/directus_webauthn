# docs/webauthn/VERIFY.md
# purpose: end-to-end checklist to confirm WebAuthn login deployment
# version: 1.0.0
# git_commit: 4ace50a
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex

## Overview
Use this checklist to prove the deployed WebAuthn endpoint build matches the repository sources and that passkey login works with existing credentials. These steps avoid cached/stale extensions by validating the build fingerprint and by exercising the start/finish contract that reactapp2 uses.

## Prerequisites
- Set `WEBAUTHN_DEBUG=true` on the Directus instance to expose the build fingerprint in responses.
- Export environment variables:
  - DEV: `DIRECTUS_URL_DEV`, `DIRECTUS_TOKEN_DEV` (for admin-only credential inspection if needed).
  - Email used for testing: `WEBAUTHN_EMAIL`.
- Ensure the bundle from this repository is deployed from `extensions/endpoints/webauthn/` into the server-side `webauthn/` folder so `/webauthn/*` serves the current build.
- Run `tools/webauthn/verify_storage.sh --mode dev` (or `--mode prod`) to assert the storage schema uses UUID primary keys and CRUD works end-to-end before manual login tests.

## Steps
1. **Confirm build fingerprint**
   ```bash
   curl -sS -X POST "${DIRECTUS_URL_DEV}/webauthn/login/start" \
     -H 'content-type: application/json' \
     -d "{\"email\":\"${WEBAUTHN_EMAIL}\"}" | jq .build
   ```
  Verify `name` is `webauthn`, `version` matches `package.json`, and `git` matches the deployed commit.

2. **Check allowCredentials and challenge**
   - Ensure the response contains `options.challenge`.
   - If credentials exist for the user, `options.allowCredentials` should be an array of base64url `id` strings (may be empty for resident credentials but never undefined when debug is enabled).

3. **Login finish negative test**
   - Repost the captured `/login/finish` payload from HAR (with the original challenge) and expect `401 INVALID_CREDENTIALS`, never `500`.

4. **Real browser test**
   - From reactapp2, trigger passkey login for the same email.
   - Expect a browser prompt even if `allowCredentials` is empty (resident keys).
   - Successful finish should return Directus tokens and increment `webauthn_credentials.sign_count` for the credential.

5. **Deployment drift check**
   - If fingerprint is missing or incorrect, inspect `/directus/extensions/endpoints/` on the server and remove or rename stale `webauthn*` folders, then redeploy the bundle from this repo.

## Troubleshooting
- `INVALID_CREDENTIALS` immediately on start: verify the user email exists (case-insensitive) and `webauthn_credentials` rows have canonical base64url `credential_id` values.
- Browser prompt not shown: ensure `/login/start` returns `200` with a challenge; resident keys work with empty `allowCredentials` arrays.
- `counter`/`sign_count` issues: confirm the stored credential maps to the presented `credential.id` after canonicalization; if not, normalize `credential_id` values to base64url.

## Manual verification (DEV)

```bash
# Health (sanitized summary in WEBAUTHN_MODE=dev)
curl -sS <DIRECTUS_BASE_URL>/webauthn/ | jq

# Session-required credential listing
curl -sS --cookie "directus_refresh_token=<session_cookie>" <DIRECTUS_BASE_URL>/webauthn/credentials | jq

# Login start (passkey)
curl -sS -X POST <DIRECTUS_BASE_URL>/webauthn/login/start \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com"}' | jq

# Dry run options (authenticated)
curl -sS -X POST <DIRECTUS_BASE_URL>/webauthn/drytest/options \
  --cookie "directus_refresh_token=<session_cookie>" \
  -H 'Content-Type: application/json' -d '{}' | jq
```
