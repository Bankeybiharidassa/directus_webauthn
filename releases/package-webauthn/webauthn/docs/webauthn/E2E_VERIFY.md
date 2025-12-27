# docs/webauthn/E2E_VERIFY.md
# purpose: operator runbook for Directus 11 + WebAuthn login end-to-end verification
# version: 1.0.0
# git_commit: d1aa92b
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex

## Scope
This runbook verifies the Directus 11 session contract, WebAuthn registration persistence, and ReactApp2 login flow against **<DIRECTUS_HOST>**.

## Prerequisites
- Export credentials used for Directus login:
  - `DIRECTUS_LOGIN_EMAIL` and `DIRECTUS_LOGIN_PASSWORD` (or `WEBAUTHN_EMAIL` / `WEBAUTHN_PASSWORD`).
- Ensure `env file` contains DEV URLs and `DIRECTUS_TOKEN_DEV` for diagnostics.
- Ensure the WebAuthn extension deployed at `/webauthn/*` is the build from this repo.

## Step 0 — Baseline auth contract (session)
```bash
curl -sS -c /tmp/webauthn.cookies -X POST "<DIRECTUS_BASE_URL>/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"<email>","password":"<password>","mode":"session"}' | jq '{data: .data, errors: .errors}'

curl -sS -b /tmp/webauthn.cookies "<DIRECTUS_BASE_URL>/users/me" | jq '{data: .data, errors: .errors}'
```
Expected: `/users/me` returns HTTP 200 and a valid user payload.

## Step 1 — WebAuthn options endpoints
```bash
curl -sS -b /tmp/webauthn.cookies -X POST "<DIRECTUS_BASE_URL>/webauthn/registration/options" \
  -H 'Content-Type: application/json' \
  -d '{"email":"<email>","identifier":"<email>"}' | jq '{ok: .ok, publicKey: .publicKey, error: .error}'

curl -sS -X POST "<DIRECTUS_BASE_URL>/webauthn/authentication/options" \
  -H 'Content-Type: application/json' \
  -d '{"email":"<email>","identifier":"<email>"}' | jq '{ok: .ok, publicKey: .publicKey, error: .error}'
```
Expected: both return HTTP 200 with `publicKey.challenge` and `publicKey.rpId` present.

## Step 2 — Registration (browser)
1. Sign in to reactapp2 (session mode).
2. Navigate to **Profile → Passkeys** and click **Add passkey**.
3. Complete the browser passkey prompt.
4. Confirm a new row in `webauthn_credentials` for the user (Directus admin).

Expected: registration verify returns 200 and the credential is persisted.

## Step 3 — Authentication (browser)
1. Sign out.
2. Use **Sign in with passkey**.
3. After the prompt, ensure the next request to `/users/me` succeeds (session cookie present).

Expected: passkey login returns 200, session is established, and `/users/me` succeeds.

## Scripted verification
Use the deterministic curl checks:
```bash
./tools/webauthn_e2e_verify.sh --mode dev --email <email> --password <password>
```

## Notes
- WebAuthn verify steps require a real browser prompt; curl cannot complete the ceremony.
- For cookie/session mode, confirm `SESSION_COOKIE_NAME` and `REFRESH_TOKEN_COOKIE_NAME` align with the Directus 11 defaults if not overridden.
