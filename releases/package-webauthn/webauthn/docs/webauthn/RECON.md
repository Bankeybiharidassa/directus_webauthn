# WebAuthn Reconnaissance

## Backend extension
- **Extension root**: `extensions/endpoints/webauthn/`.
- **Route handlers**: `extensions/endpoints/webauthn/src/index.ts` implements `/webauthn/registration/*` and `/webauthn/authentication/*` using `@simplewebauthn/server`.
- **Config/resolution**: `extensions/endpoints/webauthn/src/env.ts` parses `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGINS`, and `WEBAUTHN_TIMEOUT_MS` with host-aware fallbacks.
- **Credential normalization**: `extensions/endpoints/webauthn/src/index.ts` builds `allowCredentials` lists from stored credential IDs.
- **Challenge storage**: Directus collection `webauthn_challenges` holds challenge, type, user, and expiry rows instead of in-memory maps.
- **Credential storage**: Directus collection `webauthn_credentials` stores credential id/public key/counter, transports, and metadata via `ItemsService`.

## Frontend references
- **ReactApp2 WebAuthn client**: `reactapp2/src/lib/webauthn.ts` handles `navigator.credentials.create/get`, logging, and POSTing to `/webauthn/*`.
- **Profile UI**: `reactapp2/src/modules/Profile/PasskeyManager.jsx` lists credentials and triggers registration/authentication via the helpers.
- **Codec**: `reactapp2/src/webauthn/webauthnCodec.ts` converts backend JSON into browser `PublicKeyCredential*` options.

## RP / Origin computation
- `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGINS` are validated in `extensions/endpoints/webauthn/src/env.ts`, rejecting schemes/paths and enforcing host alignment; optional `WEBAUTHN_TIMEOUT_MS` sets the generated option timeout (default 60000ms).
- Requests are normalised through `resolveConfigForRequest` (same file) to select rpId/origin per mode and build metadata.

## Challenge storage
- Registration and authentication challenges are persisted in `webauthn_challenges` with expiry windows enforced per user and type.

## Credential storage
- Directus collection `webauthn_credentials` is used for persisted credentials. Accessed via `ItemsService` in `extensions/endpoints/webauthn/src/index.ts` (read/insert/update) and normalized in `src/utils/credentials.ts`.
- Schema expectations are documented in `extensions/endpoints/webauthn/README.md` and `docs/webauthn/SCHEMA_SNAPSHOT_DEV.md`; required fields include `id`, `credential_id`, `public_key`, `sign_count`, `user`, and timestamps.

## Existing docs/tests
- Contract and verification docs live under `extensions/endpoints/webauthn/CONTRACT.md`, `VERIFY_WEBAUTHN_BROWSER_PROMPT.md`, and `VERIFY_ENROLLMENT_FLOW.md`.
- Jest tests under `extensions/endpoints/webauthn/src/__tests__/` cover option generation, credential decoding, and challenge validation.
