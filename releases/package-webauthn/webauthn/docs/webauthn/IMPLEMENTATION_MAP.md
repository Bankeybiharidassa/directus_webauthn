# WebAuthn Implementation Map

## Entry points
- **Extension mount**: `extensions/endpoints/webauthn/src/index.ts` → calls `registerWebauthnRoutes` from the shared router.
- **Shared router**: `extensions/endpoints/_shared/webauthn-router/index.ts` registers handlers for all WebAuthn routes.

## Registered routes
- `GET /webauthn/health`
- `GET /webauthn/credentials`
- `POST /webauthn/registration/options`
- `POST /webauthn/registration/verify`
- `POST /webauthn/authentication/options`
- `POST /webauthn/authentication/verify`
- `POST /webauthn/login/start` (alias → authentication options)
- `POST /webauthn/login/finish` (alias → authentication verify)
- `POST /webauthn/drytest/options` (alias → registration options)
- `POST /webauthn/drytest/verify` (alias → registration verify)

## Storage usage
- Canonical collections resolved via `extensions/endpoints/_shared/webauthn-router/storage-names.ts` exporting `CREDENTIALS_COLLECTION` and `CHALLENGES_COLLECTION`.
- Schema checks and diagnostics implemented in `extensions/endpoints/_shared/webauthn-router/storage.ts`.

## Tooling
- Provisioning: `tools/provision_webauthn_storage.ts` wrapper for provisioning (Python backend).
- Collection-level provisioning logic: `tools/provision_webauthn_collection.py` (uses Directus schema API).
- Drift/audit scripts: `tools/audit_webauthn_collections.sh`, `tools/webauthn_compliance_check.sh`.
- Verification: `tools/verify_webauthn_storage.py` checks live Directus schema against the compliance rules.
