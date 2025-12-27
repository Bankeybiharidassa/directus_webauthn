# React WebAuthn Client Contract

This document inventories the WebAuthn HTTP calls in `reactapp2/` as currently implemented.

## Canonical base
- All requests default to the Directus extension mounted at **`/webauthn`**.
- Base is resolved via `reactapp2/src/config/webauthn.ts` and no longer falls back to `/webauthn-auth`.

## Endpoints and payloads

### Registration
- **POST `/webauthn/registration/options`** — body `{ email, nickname? }`.
  - Expected response keys: `{ publicKey, mode? }`.
- **POST `/webauthn/registration/verify`** — body `{ email, credential }` where `credential` is produced by `credentialToRegistrationJSON`.
  - Expects tokens/session to be issued on success.

### Authentication (login)
- **POST `/webauthn/authentication/options`** — body `{ email, identifier }`.
  - Expected response keys: `{ data: { attemptId?, publicKey }, mode? }`.
- **POST `/webauthn/authentication/verify`** — body `{ email, identifier, credential, attemptId? }` where `credential` is produced by `credentialToAssertionJSON`.

### Dry test (profile)
- **POST `/webauthn/drytest/options`** — body `{}` (requires session cookie).
  - Expected response keys: `{ data: { attemptId?, publicKey }, mode? }`.
- **POST `/webauthn/drytest/verify`** — body `{ credential, attemptId? }` using `credentialToAssertionJSON`.
  - Response is interpreted for `{ matchedUserCredential, usedKey, credential_id, deviceType, error? }`.

### Credential management
- **GET `/webauthn/credentials`** — returns `{ data: [...] }` where each entry may contain `id`, `credential_id`, `nickname`, timestamps, `transports`, `aaguid`, counters.
- **DELETE `/webauthn/credentials/:id`** — deletes the credential for the current user; response `{ ok: true, deleted: id }`.

## Notes
- Browser calls are mediated through `reactapp2/src/api/auth.ts` using Axios via `reactapp2/src/lib/http.ts`.
- All binary WebAuthn fields are expected to be base64url strings in JSON. Client-side conversions live in `reactapp2/src/lib/webauthn/codec.ts` and `reactapp2/src/lib/webauthn-contract.ts`.
