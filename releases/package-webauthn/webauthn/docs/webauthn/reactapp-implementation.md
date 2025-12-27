# file: docs/webauthn/reactapp-implementation.md
# purpose: describe ReactApp2 WebAuthn adapter, logging, and UI flows aligned to the endpoint contract
# version: 1.2.1
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: DEV
# last_reviewed_by: codex
# last_reviewed_at: 2025-12-24T23:16:16Z

## Single adapter (codec)

- Path: `reactapp2/src/lib/webauthn/codec.ts`
- Responsibilities:
  - `base64urlToUint8Array` / `uint8ArrayToBase64url` centralize ArrayBuffer ↔ base64url.
  - `toPublicKeyCredentialCreationOptions(raw)` → `{ publicKey: { rp, user.id (Uint8Array), challenge (Uint8Array), pubKeyCredParams, excludeCredentials ids as Uint8Array, … } }`
  - `toPublicKeyCredentialRequestOptions(raw)` → `{ publicKey: { rpId, challenge (Uint8Array), allowCredentials ids as Uint8Array, … } }`
- `credentialToJSON(cred)` encodes `rawId`, `clientDataJSON`, `attestationObject`/`authenticatorData`, `signature`, `userHandle`, `transports` to base64url for server POST.
- `deriveAaguidFromAttestation` parses the attestationObject CBOR to surface AAGUID for UI and logging; ignored by the server payload.
- `buildCredentialPreview` packages `{ credentialId, transports, aaguid }` for UI highlights.

## Browser invocation guardrails

- Callers use `CredentialCreationOptions` / `CredentialRequestOptions` **with a `publicKey` property**.
- `requestRegistration` / `requestAuthentication` (in `src/lib/webauthn.ts`) refuse to call WebAuthn APIs if:
  - `publicKey` is missing
  - `publicKey.rp` (id + name) is missing (registration)
  - `publicKey.challenge` or `publicKey.user.id` is missing
  - `publicKey.rpId` is missing (authentication/dry-test)
- DEV/WEBAUTHN_MODE=dev logging prints **only** keys, lengths, rp/rpId, and list counts (no raw challenges or IDs). PROD stays minimal unless explicitly debugged via `?debug=webauthn`.

## Flows wired to the contract

- **Registration** (`Profile/PasskeyManager.jsx`)
  - `POST /webauthn/register/start` → `parseWebAuthnOptions(..., "registration")` → `toPublicKeyCredentialCreationOptions`.
  - `navigator.credentials.create(options)` with rp present.
  - `credentialToJSON` payload POSTed to `/register/finish`; on success the credential list is reloaded.
  - UI shows credential ID preview, createdAt, transports, and AAGUID (derived from attestationObject) and highlights the newest credential (“New” chip).

- **Authentication** (`state/AuthContext.jsx`)
  - `POST /webauthn/login/start` → `parseWebAuthnOptions(..., "authentication")` → `toPublicKeyCredentialRequestOptions`.
- `navigator.credentials.get(options)` with rpId + allowCredentials decoded.
- `credentialToJSON` payload POSTed to `/login/finish` with `loginAttemptId`.
- Session validation: after finish, `fetchCurrentUser` (`/users/me` with `withCredentials`) must succeed; otherwise the login is treated as failed.

- **Dry-test** (`Profile/PasskeyManager.jsx`)
  - `POST /webauthn/drytest/options` → `parseWebAuthnOptions(..., "authentication")` → `toPublicKeyCredentialRequestOptions`.
  - `navigator.credentials.get(options)` with rpId present; payload POSTed to `/drytest/verify` with `dryTestAttemptId`.
  - Response drives a banner showing `{ ok, matched, belongsToUser }` plus `credential_id`, `credential_name`, `deviceType`, `transports`, and counters; no auth state change.

## Logging policy

- ENV-driven: `env file` `WEBAUTHN_MODE=dev` (or Vite DEV) enables verbose WebAuthn debug logging automatically. `WEBAUTHN_MODE=prod` keeps logs minimal.
- Query override: `?debug=webauthn` also enables debug logging (sanitized).
- Sanitization: logs include key sets, rp/rpId presence, `challenge`/`user.id` lengths, allow/exclude counts, and navigator errors (name/message) only.

## Schema alignment (DEV snapshot)

- Live DEV schema (`docs/webauthn/SCHEMA_SNAPSHOT_DEV.json`) includes `nickname` but no `name`/`type` on `webauthn_credentials`. UI labels must use `nickname` (fallback “Passkey”) and metadata only.
