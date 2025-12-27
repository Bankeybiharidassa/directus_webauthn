# docs/webauthn/DEV_CREDENTIAL_MATCH.md
# purpose: reproduce credential-to-user mapping in DEV with curl
# version: 1.0.0
# git_commit: TBA
# git_repo: https://github.com/itssecured/kibana2directus
# mode: DEV
# last_reviewed_by: codex
# last_reviewed_at: 2025-12-15

## What was matched
- Credential ID: `FLKbG-m8F34DuOaz0P2sk80Y-ToCF6SPLD4peTdFK3k`
- Located row: `webauthn_credentials.id=4` with `sign_count=0` and `public_key` `pQECAyYgASFYIH+uqIHYUJnZcxiXSJ5Ux5aDUBNamQo70KgrgDcwaPYfIlggAp/aqmgnoZSSn39Srf0H0ysuSVwqaamWRilkSbSfGqE=`
- Owner: user `<DIRECTUS_USER_ID>` (`admin@example.com`) with role **Administrator** (`directus_roles.id=<ROLE_ID>`).

## How to reproduce with env file _DEV variables
All commands assume you are in the repository root and `env file` contains `DIRECTUS_URL_DEV` and `DIRECTUS_TOKEN_DEV`. Do **not** echo token values.

1) Export the DEV Directus variables without leaking secrets:
```bash
DIRECTUS_URL="${DIRECTUS_URL_DEV}"
DIRECTUS_TOKEN="${DIRECTUS_TOKEN_DEV}"
```

2) Fetch the credential row by credential_id:
```bash
CRED_ID="FLKbG-m8F34DuOaz0P2sk80Y-ToCF6SPLD4peTdFK3k"
curl --globoff -sS "${DIRECTUS_URL}/items/webauthn_credentials?limit=50&fields=id,user,credential_id,public_key,sign_count,last_used_at&filter[credential_id][_eq]=${CRED_ID}" \
  -H "Authorization: Bearer ${DIRECTUS_TOKEN}" | jq .
```

3) Fetch the owning user and role:
```bash
USER_ID="65038280-d669-47fa-a1fe-afaca4cbc82c"
curl --globoff -sS "${DIRECTUS_URL}/users/${USER_ID}?fields=id,email,role.id,role.name" \
  -H "Authorization: Bearer ${DIRECTUS_TOKEN}" | jq .
```

4) Verify the extension returns credentials for this user (proves API/collection access):
```bash
curl -sS -X POST "${DIRECTUS_URL}/webauthn/login/start" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com"}' | jq .
```
Expect a 200 response with `options.challenge`, a `loginAttemptId`, and an `allowCredentials` array that includes the credential IDs above. This confirms reactapp2 and the extension share the same credential data.

## Notes for Codex operators
- Use `--globoff` with curl to prevent bracket expansion in filter parameters.
- Keep `WEBAUTHN_DEBUG=true` in DEV when validating responses so the build fingerprint and debug logs remain visible.
- If any step fails with 401, re-check that `DIRECTUS_TOKEN_DEV` from `env file` is exported correctly and still valid via `curl -sS -H "Authorization: Bearer ${DIRECTUS_TOKEN_DEV}" "${DIRECTUS_URL_DEV}/users/me"`.
