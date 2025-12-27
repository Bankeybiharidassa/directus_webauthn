# WebAuthn Testing Guide

## Browser (DEV)
1. Sign in to ReactApp2 on `<DIRECTUS_BASE_URL>`.
2. From Profile → Passkeys, click **Test passkey (dry run)** to trigger `POST /webauthn/drytest/options` → navigator.credentials.get → `POST /webauthn/drytest/verify`.
3. Expect a success message showing `matchedUserCredential=true` and the nickname/device type of the used key.
4. For login, use the passkey button; the flow calls `/webauthn/authentication/options` → `/webauthn/authentication/verify` and should end with a valid session cookie.

## Curl snippets
```bash
BASE="<DIRECTUS_BASE_URL>"
COOKIE="$(cat cookie.txt)" # supply Directus session cookie for authenticated calls

# Credentials list
curl -sS -H "cookie: $COOKIE" "$BASE/webauthn/credentials" | jq

# Auth options
curl -sS -X POST "$BASE/webauthn/authentication/options" \
  -H 'content-type: application/json' \
  -d '{"email":"user@example.com"}' | jq

# Drytest options (requires cookie)
curl -sS -X POST "$BASE/webauthn/drytest/options" \
  -H "cookie: $COOKIE" -H 'content-type: application/json' -d '{}' | jq
```

## Node tests
- Run Vitest unit tests for the extension: `npm test --prefix extensions/endpoints/webauthn`.
- Contract probe against DEV: `node scripts/webauthn/contract-check-dev.mjs` (set `WEBAUTHN_COOKIE` for authenticated calls).
