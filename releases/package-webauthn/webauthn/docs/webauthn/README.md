# WebAuthn / Passkeys

This extension implements passkey registration and authentication via `@simplewebauthn/server` for Directus. The React portal (`reactapp2`) uses `@simplewebauthn/browser` helpers to call these endpoints.

## Endpoints
- `POST /webauthn/registration/options` — generate `PublicKeyCredentialCreationOptions` for the current user, excluding existing credentials.
- `POST /webauthn/registration/verify` — verify attestation and persist the credential to `webauthn_credentials`.
- `POST /webauthn/authentication/options` — generate `PublicKeyCredentialRequestOptions` for a given user (session or email).
- `POST /webauthn/authentication/verify` — verify assertions, bump counters, and return user identity data.

## Configuration
- `WEBAUTHN_RP_ID` — host name only (no scheme/path). Must match the site host (e.g., `<DIRECTUS_HOST>`).
- `WEBAUTHN_ORIGINS` — comma-separated list of full origins (e.g., `<DIRECTUS_BASE_URL>`). Must align with `WEBAUTHN_RP_ID`.
- `WEBAUTHN_TIMEOUT_MS` — optional timeout applied to generated options (default 60000ms).
- Tokens/secret helpers are pulled from the active env file via `env.ts`.

## Developer guide
See `docs/webauthn/DEVELOPER_GUIDE.md` for the standalone project checklist, build/test commands, environment rules, and security caveats.

## Storage
- **Credentials**: persisted in Directus collection `webauthn_credentials` with fields `id`, `credential_id`, `public_key`, `sign_count`, `user`, timestamps, and metadata (nickname, origin, user_agent, transports).
- **Challenges**: persisted in Directus collection `webauthn_challenges` with fields `id`, `user`, `challenge`, `type`, `expires_at`, `created_at`.

## Troubleshooting checklist
- Ensure `WEBAUTHN_RP_ID` exactly matches the host (no scheme/port) and `WEBAUTHN_ORIGIN` matches `window.location.origin`.
- Confirm the React client prepares options via `reactapp2/src/webauthn/webauthnCodec.ts` and posts credentials through `reactapp2/src/lib/webauthn.ts`.
- Verify the `webauthn_credentials` collection exists and is readable/writable for the service account (see `extensions/endpoints/webauthn/README.md`).
- Check logs with `?debug=webauthn` in the portal URL to trace option generation and browser calls.
- Dry-run endpoints (`/webauthn/drytest/options` and `/verify`) require an authenticated session and validate stored credentials without issuing tokens.

## How to test (DEV)
1. Load environment from `env file` (DEV) and ensure `DIRECTUS_URL_DEV` / `DIRECTUS_TOKEN_DEV` are present.
2. Call `/webauthn/registration/options` and verify `rp.id`, `rp.name`, and `challenge` are present.
3. In the React portal, enable `?debug=webauthn`, use Profile → Passkeys to register a new passkey, and confirm a row is created in `webauthn_credentials`.
4. Run authentication via `/webauthn/authentication/options` for the same user and finish in the browser.

## Files
- Backend: `extensions/endpoints/webauthn/src/index.ts`, `src/env.ts`, `src/utils/credentials.ts`.
- Frontend: `reactapp2/src/lib/webauthn.ts`, `reactapp2/src/webauthn/webauthnCodec.ts`, `reactapp2/src/modules/Profile/PasskeyManager.jsx`.
- Requirements & procedures: `docs/webauthn/REQUIREMENTS_AND_PROCEDURES.md`.
- Compliance: `docs/webauthn/COMPLIANCE_CHECKLIST.md` and `docs/webauthn/compliance_rules.json`.
