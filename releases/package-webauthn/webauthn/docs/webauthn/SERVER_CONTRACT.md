# file: docs/webauthn/SERVER_CONTRACT.md
# purpose: define Directus WebAuthn endpoint contract and response shape
# version: 1.1.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex
# last_reviewed_at: 2025-12-24T23:16:16Z

# Directus WebAuthn Server Contract

Current routes are implemented in `extensions/endpoints/webauthn/src/index.ts` via the shared router `extensions/endpoints/_shared/webauthn-router/index.ts`.

## Mounted base
- Extension name: `webauthn` → mounted at `/webauthn`.

## Routes
- `GET /webauthn/` — health payload with `status`, `rpId`, `origin`, `mode`, and env metadata.
- `POST /webauthn/registration/options` — authenticated; issues `PublicKeyCredentialCreationOptions` and stores challenge state.
- `POST /webauthn/registration/verify` — authenticated; verifies attestation response and saves credential.
- `POST /webauthn/authentication/options` — unauthenticated; resolves user by `userId` or `email`, builds `allowCredentials`, and stores challenge with `attemptId`.
- `POST /webauthn/authentication/verify` — verifies assertion for stored attempt, enforces allowed credential ids, and should create a session.
- `POST /webauthn/login/start` and `POST /webauthn/login/finish` — legacy aliases mapped to authentication handlers.
- `POST /webauthn/drytest/options` — authenticated; builds assertion options limited to the current user.
- `POST /webauthn/drytest/verify` — authenticated; verifies assertion against stored attempt and returns `{ ok, matched, belongsToUser, credential_id, credential_name, deviceType, transports, storedCounter, newCounter }` plus a legacy `{ credential: { id, label, type } }` block.
- `GET /webauthn/credentials` (and `/credentials/`) — authenticated; returns sanitized credential list for the current user.
- `DELETE /webauthn/credentials/:id` — authenticated; deletes a credential owned by the current user.

## Storage
- Challenges: `webauthn_challenges` collection (attempt id, challenge JSON, expires_at).
- Credentials: `webauthn_credentials` collection (credential_id, public_key, sign_count, transports, device metadata, timestamps).

## Logging and validation
- Dev logging is gated by `WEBAUTHN_MODE=dev` and redacts credential material via `redactCredentialPayload`.
- Base64url normalization lives in `_shared/webauthn-router/utils.ts`.
- Env parsing and rpId/origin validation live in `_shared/webauthn-router/env.ts`.
