# file: docs/webauthn/reactapp-client-contract.md
# purpose: ReactApp2 WebAuthn client contract (options parsing, codec, and request payloads)
# version: 1.0.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: DEV
# last_reviewed_by: codex
# last_reviewed_at: 2025-12-16

## Codec SSOT

- Module: `reactapp2/src/lib/webauthn/codec.ts`
- Responsibilities:
  - Convert API JSON → WebAuthn API objects:
    - `parseCreationOptionsFromJSON` → `PublicKeyCredentialCreationOptions`
    - `parseRequestOptionsFromJSON` → `PublicKeyCredentialRequestOptions`
  - Convert browser credentials → API JSON:
    - `credentialToRegistrationJSON` (attestation)
    - `credentialToAssertionJSON` (assertion)
  - Preserve `rp.id`/`rp.name`, `challenge`, `user.id`, and descriptor ids; validate required fields before WebAuthn calls (throws when `rp` is missing and logs received keys when debug is on).
  - Base64url ↔ `ArrayBuffer` for `challenge`, `user.id`, `excludeCredentials[].id`, `allowCredentials[].id`, `clientDataJSON`, `attestationObject`, `authenticatorData`, `signature`, `userHandle`.
- Debug switch: `isWebAuthnDebugEnabled()` is true when `WEBAUTHN_MODE=dev`, Vite dev, or `?debug=webauthn` is present; options/response shapes log to the console without secrets.

## React flows

### Register (Profile → Add passkey)
1. POST `/webauthn/registration/options` with `{}` while authenticated.
2. Parse options with `parseWebAuthnOptions(..., "registration")` → `{ publicKey }` where `publicKey.rp`, `challenge`, `user.id`, and `excludeCredentials` are `Uint8Array`.
3. `requestRegistration` validates required fields, logs keys when malformed, then calls `navigator.credentials.create({ publicKey })`.
4. POST `/webauthn/registration/verify` with `credentialToRegistrationJSON(credential)`; refresh credential list and surface AAGUID/transports when returned.

### Login (Sign in with passkey)
1. POST `/webauthn/authentication/options` with `{}` (auth-required for now).
2. Parse authentication options; include `loginAttemptId`.
3. `navigator.credentials.get({ publicKey })` via `requestAuthentication`.
4. POST `/webauthn/authentication/verify` with `credentialToAssertionJSON(credential)` and optional `loginAttemptId`; expect tokens/session cookie and `/users/me` success.

### Dry-test (Profile → Test my passkey)
1. POST `/webauthn/drytest/options` (auth required). Options include `allowCredentials` for the current user and `dryTestAttemptId`.
2. `navigator.credentials.get({ publicKey })`.
3. POST `/webauthn/drytest/verify` with `credentialToAssertionJSON(credential)` + `dryTestAttemptId`.
4. UI messages:
   - `belongsToUser=true`: “Passkey verified and linked to your user.”
   - `belongsToUser=false`: “Passkey verified but is not linked to this user.”
   - Display `credential.idShort`, `label`, `type` (authenticatorAttachment), `aaguid` (if available).

## Error handling expectations

- Missing `rp` or `challenge` now throws in the codec before invoking WebAuthn APIs; errors include the received option keys when debug is enabled.
- Authentication/registration failures surface Directus errors; dry-test verify returns `{ ok: false }` via HTTP error semantics (non-2xx).
- Browser support guards: `isWebAuthnSupported` + secure context check block flows with actionable messages.
