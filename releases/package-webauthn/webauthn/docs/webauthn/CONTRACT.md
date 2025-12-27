# WebAuthn Endpoint Contract

## Common rules
- Authenticated Directus user is inferred from the request session/bearer token; request bodies never require `email` for normal flows.
- Requests/Responses use `application/json`.
- Errors are returned as `{ ok:false, error:<code>, message:<text>, details?:{}, reason?:<dev> }`.
- Logging:
  - DEV (`WEBAUTHN_MODE=dev` or `NODE_WEBAUTHN_MODE=development`): log request ID, route, hostname/rpId, missing env vars, and stack traces; never log credential secrets.
  - PROD: log only request ID, route, and stable error code.
- Public diagnostics are redacted: unauthenticated callers see only coarse health booleans.
  - Detailed diagnostics are returned only when `NODE_WEBAUTHN_MODE=development` **or** `WEBAUTHN_DIAGNOSTICS_PUBLIC=true`.
  - When diagnostics are not explicitly public, the caller must be an admin/service account to see details.
  - Error detail payloads that include schema/env hints (e.g., `missing`, `provisionCommand`) follow the same diagnostics policy.

## Canonical endpoints and aliases
- Canonical WebAuthn routes live under `/webauthn`:
  - Registration: `/registration/options`, `/registration/verify`
  - Authentication: `/authentication/options`, `/authentication/verify`
- Aliases are provided for legacy ReactApp2 wiring and must resolve to the same handlers/responses as the canonical endpoints:
  - `/login/start` → `/authentication/options`
  - `/login/finish` → `/authentication/verify`
  - `/otp/options` and `/otp/verify` → dry-test profile checks (non-crypto)
  - `/drytest/options` and `/drytest/verify` → dry-test profile checks (non-crypto)

## Credential listing
- **GET `/webauthn/credentials`** (requires authenticated user)
- Response: `{ ok:true, credentials:[{ id, label, type, created_at, last_used_at }] }` with `type` mapped to `platform|cross-platform|unknown`.
- Never depends on WebAuthn crypto config; returns `credentials: []` when none exist.

## Registration (credential enrolment)
### Create attestation options
- **POST `/webauthn/registration/options`**
- Body: `{}` (uses session user) or `{ "userId"|"userIdOverride": "<directus_id>" }` for administrative enrolment.
- Success response: `{ ok:true, publicKey:{ challenge, rp, user, timeout }, context:{ flow:'registration', user_id, request_id, issued_at } }`.

### Verify attestation
- **POST `/webauthn/registration/verify`**
- Body: browser credential response under `credential` plus optional `credentialName` for labelling.
- Success response: `{ ok:true, data:{ credentialId, userId } }`.
- Input validation failures → 400 `invalid_webauthn_response`.

## Authentication (login/session creation)
### Create assertion options
- **POST `/webauthn/authentication/options`**
- Body: `{}` or `{ "username"|"email"|"identifier": "user@example.com" }` when starting from a logged-out state. Client-supplied `rpId` values are ignored; the server derives the relying party identifier from configuration.
- Success response: `{ ok:true, publicKey:{ challenge, timeout, rpId, allowCredentials, userVerification }, context:{ flow:'auth', user_id, request_id, issued_at } }`.
- Username-less passkey flows are supported: when no session or username is provided, the server returns an empty `allowCredentials` list and `context.user_id: null` so discoverable credentials can be used.
- If `username` is provided but does not resolve to a Directus user, the server responds with `{ ok:false, error:'webauthn_user_not_found', message:'User not found for WebAuthn login.' }`.

### Verify assertion
- **POST `/webauthn/authentication/verify`**
- Body: browser credential response with `id/rawId`, `type`, and `response.{authenticatorData,clientDataJSON,signature,userHandle}`; `attemptId/requestId` optional (falls back to latest challenge).
- Success response: `{ ok:true, result:{ credential_id, label, type, expires? }, context:{ flow:'auth', user_id, request_id } }` and issues a Directus session/refresh pair or returns the unsupported error above.
- Input validation failures → 400 `invalid_webauthn_response`.
- User verification enforcement follows policy: `requireUserVerification` is `true` only when `WEBAUTHN_USER_VERIFICATION=required`; `preferred` does not force UV, and `discouraged` does not require it.

## Profile dry-test (OTP-like)
### Options
- **POST `/webauthn/otp/options`** (aliases: `/drytest/options`)
- Body: `{}`
- Response mirrors authentication options with `context.flow: 'drytest'` and `context.request_id`.

### Verify
- **POST `/webauthn/otp/verify`** (aliases: `/drytest/verify`)
- Body: same as authentication verify.
- Success: `{ ok:true, match:true, credential:{ id, label, type } }`.
- If credential valid but not owned by user: `{ ok:true, match:false, error:'credential_not_owned', message:'Credential is valid, but not registered under this user.' }`.

## Configuration
- Required keys for crypto routes: `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGIN`, `WEBAUTHN_STORAGE_COLLECTION` (with defaults derived from request host when missing).
- Missing keys → HTTP 503 `{ ok:false, error:'webauthn_not_configured', details:{ missing:[...] } }`.
- Storage defaults: credentials in `webauthn_credentials`; challenges in `webauthn_challenges`.
