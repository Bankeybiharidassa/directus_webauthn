# Requirements and Procedures for WebAuthn

## Scope and goals
Goal: Provide a complete WebAuthn (Passkeys/FIDO2) module that supports:

- Registration (credential creation / attestation)
- Authentication (assertion / login)
- Credential lifecycle: list, rename, delete, optional “require re-auth”, optional “step-up”
- Multi-device passkeys and platform authenticators (Touch ID / Windows Hello / Android)
- Roaming security keys (YubiKey, etc.)
- Strong anti-phishing and replay protection
- Standards-compliant handling of WebAuthn structures and encodings

Non-goals (explicitly):

- Not inventing custom crypto or challenge formats
- Not storing secrets client-side
- Not accepting “client passes rpId/origin” as truth

## Standards baseline (what “compliant” means)
Your module must implement the relevant parts of:

- W3C WebAuthn Level 2/3 (PublicKeyCredential, create/get ceremonies, attestation/assertion formats, clientDataJSON, authenticatorData)
- FIDO2 / CTAP2 (authenticator behavior, flags in authenticatorData, AAGUID, signCount semantics)
- IANA COSE / CBOR keys and algorithms (ES256, RS256 if allowed, EdDSA optional)
- Passkeys: multi-device, resident keys, discoverable credentials, user verification signals

Practical implication: the server must parse and verify:

- clientDataJSON (JSON)
- attestationObject (CBOR → authenticatorData + attStmt)
- authenticatorData binary
- signature verification over the correct concatenation

## Architecture overview
Components:

- **Browser client** — calls `navigator.credentials.create({ publicKey })` and `navigator.credentials.get({ publicKey })`.
- **Relying Party (RP) Server Module** — generates options (challenge + policy), stores a challenge record for the ceremony, validates attestation/assertion responses, stores credential public keys & metadata, and enforces RP ID, origin, algorithm policy, UV/UP policy, and replay protection.
- **Persistence layer** — credentials table/collection, challenges table/collection, and optional audit table.

Flows (minimum):

- Registration: `POST /webauthn/registration/options` → browser `create()` → `POST /webauthn/registration/verify`
- Authentication: `POST /webauthn/authentication/options` → browser `get()` → `POST /webauthn/authentication/verify`
- Legacy aliases remain supported for ReactApp2: `/webauthn/login/start` ⇢ authentication/options, `/webauthn/login/finish` ⇢ authentication/verify, `/webauthn/login/verify` ⇢ authentication/verify, `/webauthn/register/start` ⇢ registration/options, `/webauthn/register/finish` ⇢ registration/verify, `/webauthn/registration/start` ⇢ registration/options, `/webauthn/registration/finish` ⇢ registration/verify.
- Health and diagnostics endpoints must respond without authentication: `GET /webauthn/` (alias) and `GET /webauthn/health` expose storage/config availability; `GET /webauthn/diag` (gated by `WEBAUTHN_DEBUG=true`) returns build fingerprint, config, and storage audit.

## Security requirements (hard requirements)
RP / origin binding — the server MUST reject if:

- `clientDataJSON.type` mismatch (`webauthn.create` or `webauthn.get`).
- `clientDataJSON.origin` is not in the allowlist (exact match, including scheme and host and port).
- `rpId` used in options isn’t your configured rpId (server-owned).
- `rpIdHash` in `authenticatorData` doesn’t match `SHA-256(rpId)`.

Challenge protection:

- Challenge MUST be cryptographically random (≥ 16 bytes; recommended 32) and base64url encoded without padding when sent to the browser.
- Challenge MUST be stored server-side with user reference (if known), type (registration/authentication), `expires_at` (recommended 5 minutes), and `used_at` (single-use).
- Verification MUST check challenge exists, not expired, not used, and challenge equals `clientDataJSON.challenge`.
- Default TTL: 60 seconds (configurable via `WEBAUTHN_TIMEOUT_MS`, default 60000). Health/options calls must also prune expired challenges and any `used_at` older than 5 minutes.
- After successful registration/authentication verification, delete the consumed challenge row (or mark `used_at` and purge within 5 minutes) to minimize replay surface.

Replay and session binding:

- Mark challenge as used atomically.
- Optional: bind challenge to session id, CSRF token, or a signed server cookie.

TLS and headers:

- Must be served over HTTPS.
- Use strict Content-Security-Policy, X-Frame-Options/frame-ancestors, Referrer-Policy, etc.
- Authentication endpoints should require CSRF defense if cookie-based.

Credential storage security:

- Store public keys, never private keys.
- Credential IDs are not secret but should be treated as identifiers.
- Protect at rest (DB encryption if available) and access controlled.

Algorithm policy (recommended):

- Allow ES256 (COSE -7) as default.
- Allow RS256 only if needed.
- Consider allowing EdDSA only if the stack supports it correctly.
- Reject unsupported algorithms.

User verification policy:

- For login, set userVerification policy explicitly: preferred for standard UX, required for high-risk areas.
- Enforce policy by checking flags in `authenticatorData`: UP (User Presence) and UV (User Verification). If required and UV not set → reject.

Sign counter (`signCount`):

- Track signCount and enforce monotonic increase as a signal (some authenticators always return 0).
- If a previously-seen credential suddenly decreases → flag as suspicious; choose fail/alert depending on policy.

## Data model requirements
Credentials table (required fields only):

- user (subject reference)
- credential_id (bytea/base64url)
- public_key (COSE key bytes or converted to JWK/SPKI)
- sign_count (int, default 0)

Credentials table (optional fields):

- transports (array of strings)
- aaguid (uuid)
- device_type (platform/cross-platform)
- backed_up (bool) optional (from BE flag when available)
- nickname (string)
- user_agent (string)
- origin (string) optional (store observed origin for audit)
- rp_id (string)
- last_used_at (timestamp)
- created_at, updated_at (timestamps)
- credential_uuid (string)
- cose_alg (int)
- email (string)

Challenges table (required fields only):

- challenge_id
- challenge (bytes/base64url)
- type enum: registration/authentication
- expires_at

Challenges table (optional fields):

- user nullable (for username-less/discoverable flows)
- used_at nullable
- rp_id
- origin
- created_at

Users: must have a stable unique ID used as WebAuthn user.id (bytes). Requirement: not email, not mutable. Use UUID bytes.

### Storage contract: canonical collections, flexible primary keys

- Collections **must** be named exactly `webauthn_credentials` and `webauthn_challenges`; overrides and aliases are drift.
- Primary keys may be integer or UUID. Integer PKs remain supported; UUID PKs are optional and must never be enforced as a prerequisite.
- All schema changes and repairs must go through Directus routes (collections/fields/relations). Direct SQL routes or database shell clients are forbidden for WebAuthn provisioning.
- Challenge correlation uses a dedicated `webauthn_challenges.challenge_id` string field. The Directus primary key `id` is left untouched.
- Credentials keep their Directus `id` intact; credential uniqueness relies on `credential_id` and (optionally) `credential_uuid` for tracing.
- Validation/health must only fail when collections/fields are missing. PK type mismatches surface as diagnostics/warnings, not blocking errors.
- Provisioning (`tools/provision_webauthn_storage_directus.py --mode dev --env env file`) verifies and ensures required collections/fields exclusively via Directus routes. It does not require DB credentials or any PK migration path.
- Periodic cleanup (`tools/cleanup_webauthn_challenges_directus.py --mode dev --env env file`) prunes expired challenges and used challenges older than five minutes.
- Diagnostics (`tools/diag_webauthn_http.py --mode dev --env env file`) validate routes, storage schema, and can optionally exercise dry-test verification.
- Verify the contract end-to-end with `tools/webauthn/verify_storage.sh --mode dev|prod --env-path <env>`; it asserts collection names/fields (including `challenge_id`) and round-trips challenges/credentials.

### Supported environment variables (set in the extensions env, e.g., `/home/directus/extensions_b/env file`)

- `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGINS` (comma-separated HTTPS origins), `WEBAUTHN_TIMEOUT_MS` (default: 60000)
- Optional tuning: `WEBAUTHN_USER_VERIFICATION`, `WEBAUTHN_DIAGNOSTICS_PUBLIC`, `WEBAUTHN_ENV_PATHS`, `WEBAUTHN_ENV_FILE`
- Defaults for `WEBAUTHN_ORIGINS` derive from the server’s own origin when unset; missing values surface as clear `/webauthn/health` diagnostics without blocking startup.

## Registration ceremony requirements
Options endpoint must produce `PublicKeyCredentialCreationOptions` with:

- rp: id (server configured rpId, e.g., `<DIRECTUS_HOST>`) and name (display name)
- user: id (stable bytes/base64url), name (username/email string), displayName (friendly name)
- challenge: random bytes base64url
- pubKeyCredParams: ES256 first with optional fallback list
- timeout: e.g., 60000
- attestation: recommended default `none` (privacy-preserving); if `direct`, handle attestation trust chain policy
- authenticatorSelection: residentKey `preferred`, requireResidentKey false, userVerification `preferred` or `required`, authenticatorAttachment optional
- excludeCredentials: include existing credentials to prevent duplicates (optional but recommended)

Verify endpoint must validate:

- `clientDataJSON` parse; verify `type == webauthn.create`, origin allowlist, challenge match
- `attestationObject` CBOR parse → extract `authData`, `fmt`, `attStmt`
- Parse `authData`: `rpIdHash` match, flags check (UP must be set; UV if required), signCount, attestedCredentialData present (AAGUID, credentialId, credentialPublicKey COSE_Key)
- Attestation verification: if `attestation="none"` skip chain validation but verify structure; if direct/indirect validate fmt-specific signatures/certs per spec
- Store credential: ensure credentialId uniqueness, store COSE key and metadata, mark challenge as used

## Authentication ceremony requirements
Options endpoint must support two modes:

- **Username-first (non-discoverable):** client provides username/email; server looks up user credentials, returns `allowCredentials` list, sets userVerification policy, and stores challenge.
- **Username-less (discoverable / passkeys):** client does not provide username; server returns empty `allowCredentials` (or omit). After verify, find user based on matched credentialId in DB.

Verify endpoint must validate:

- Parse `clientDataJSON`: `type == webauthn.get`, origin allowlist, challenge match
- Parse `authenticatorData`: `rpIdHash` match; flags UP required and UV if policy requires; capture signCount
- Identify credential record via `rawId / id` (base64url → bytes)
- Verify signature over `authenticatorData || SHA256(clientDataJSON)` using stored public key (COSE → verification key)
- Update credential: `last_used_at`, sign_count policy handling
- Mark challenge used; return authenticated subject + session token (per auth system)

## Encodings and wire format requirements (critical)

- Base64URL (no padding) for all binary fields in JSON (including `id`, `rawId`, `response.clientDataJSON`, `response.attestationObject`, `response.authenticatorData`, `response.signature`, `response.userHandle`).
- WebAuthn uses exact JSON field names; don’t rename.
- Registration response object: `id`, `rawId`, `type`, `response.clientDataJSON`, `response.attestationObject`, optional `response.transports`.
- Authentication response object: `id`, `rawId`, `type`, `response.clientDataJSON`, `response.authenticatorData`, `response.signature`, optional `response.userHandle`.

## API contract (recommended minimal endpoints)
Registration:

- `POST /webauthn/registration/options` — input: `{ userId?, username?, displayName?, authenticatorAttachment?, userVerificationPolicy? }`; output: `PublicKeyCredentialCreationOptions` (+ server metadata if needed).
- `POST /webauthn/registration/verify` — input: `{ credential: <PublicKeyCredential>, challengeId? }`; output: `{ ok: true, credentialId, nickname?, aaguid?, createdAt }`.

Authentication:

- `POST /webauthn/authentication/options` — input: `{ username? }`; output: `PublicKeyCredentialRequestOptions`.
- `POST /webauthn/authentication/verify` — input: `{ credential: <PublicKeyCredential>, challengeId? }`; output: `{ ok: true, userId, sessionToken? }`.

Credential management (optional but normal):

- `GET /webauthn/credentials`
- `PATCH /webauthn/credentials/:id` (rename)
- `DELETE /webauthn/credentials/:id`

Health and diagnostics:

- `GET /webauthn/health` (and `/webauthn/`) — must return `{ ok: true, storage: { available: true } }` when storage is intact

## Policy knobs (config requirements)

- `RP_ID` (e.g., `<DIRECTUS_HOST>`)
- `RP_NAME` (display)
- `ORIGIN_ALLOWLIST` (array)
- `CHALLENGE_TTL_SECONDS` (default 300)
- `ATTESTATION` (none default)
- `USER_VERIFICATION_DEFAULT` (preferred default)
- `RESIDENT_KEY` (preferred)
- `ALLOWED_COSE_ALGS` (default [-7])
- `REQUIRE_UV_FOR` (routes/roles) optional
- `CLOCK_SKEW_SECONDS` (default small tolerance)
- `MAX_CREDENTIALS_PER_USER` (optional)
- `AUDIT_LOG_ENABLED` (optional)

## Attestation policy (what you must decide)

- If `attestation: "none"`, you don’t verify device identity (most privacy friendly, simplest).
- If `attestation: "direct"`, you must implement trust chain validation, attestation format verification, and root store/metadata service policy (often via FIDO Metadata Service). Decide enterprise vs consumer policy. Requirement: default to none unless there is a concrete reason to do device attestation.

## Threat model checklist (must pass)

- Phishing: origin/rpIdHash enforcement is mandatory.
- Replay: single-use challenge, server-side stored.
- Credential injection: ignore client-provided rpId/origin/alg claims.
- Cross-tenant confusion (multi-tenant platforms): rpId/origin + tenant binding of user/credential records must be correct.
- Downgrade: reject algorithms outside policy.
- Session swapping: bind challenge to user/session when possible.
- DB tampering: optional integrity logs, at least strict DB permissions.

## Observability & audit requirements

- Minimum logs (structured): ceremony started (user, type, challenge id, expiry); ceremony success (user, credential id, authenticator flags, signCount); ceremony failure (reason category: origin mismatch / challenge mismatch / sig invalid / rpIdHash mismatch / etc.).
- Do not log raw credential blobs in production logs.

## Test requirements (must-have)

- Unit tests (server): base64url encode/decode correctness; clientDataJSON parsing; rpIdHash validation; signature verification with known vectors; signCount handling.
- Integration tests: headless browser or Playwright covering registration options → create() → verify and auth options → get() → verify.
- Negative tests: wrong origin; wrong challenge; expired challenge; reused challenge; wrong rpIdHash; corrupted signature.
- Compatibility tests: platform authenticator (Windows Hello / Touch ID); roaming key (YubiKey); discoverable (username-less) passkey path.

## Common implementation pitfalls (explicitly avoid)

- Treating rpId as the origin or vice versa.
- Not hashing clientDataJSON before signature verify.
- Using normal base64 instead of base64url.
- Accepting “challenge” passed from client instead of stored server-side.
- Storing user.id as a string instead of bytes.
- Assuming signCount always increments (some authenticators don’t).
