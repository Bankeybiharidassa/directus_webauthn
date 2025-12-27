# WebAuthn Rollout Plan

## DEV deployment
1. Ensure `env file` contains `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGINS`, `DIRECTUS_URL_DEV`, and `DIRECTUS_TOKEN_DEV` aligned to `<DIRECTUS_BASE_URL>`.
2. Deploy the `webauthn` extension build to the DEV Directus instance using `./install_webauthn_extension.sh --mode dev --base-pattern <target_glob>` (wrapper calls the tools/ installer) and restart the extensions service. If `./tools/install_webauthn_extension.sh` is missing on a fresh clone, pull latest main and ensure the repository checkout is complete before retrying with `./install_webauthn_extension.sh --help`.
3. Verify health by calling `POST /webauthn/registration/options`; confirm `rp.id` and `challenge` are present.
4. Complete a full registration + login cycle through ReactApp2 (`?debug=webauthn`) and confirm `webauthn_credentials` receives a new row and `webauthn_challenges` entries expire after verification.
5. Run `scripts/webauthn_acceptance_dev.sh` to validate option shape responses.

## PROD deployment (after DEV sign-off)
1. Mirror the `env file` values to `<ENV_FILE_PATH>` with PROD host/origin values.
2. Promote the built extension to the PROD Directus instance following the standard operator promotion steps.
3. Re-run the option probes against PROD URLs and confirm permissions on `webauthn_credentials` allow inserts/updates for authenticated users.
4. Monitor logs for `webauthn` routes; ensure counters are incrementing and challenges clear after verification.

## Verification
- Registration options: presence of `rp`, `challenge`, and a timeout aligned with `WEBAUTHN_TIMEOUT_MS`.
- Authentication options: presence of `challenge`, `rpId`, and populated `allowCredentials` for the target user.
- Stored credentials: `credential_id`, `public_key`, `sign_count`, `user`, and timestamps updated on successful assertions.

## Route base
- Canonical base path: `/webauthn/*` served by the `extensions/endpoints/webauthn/` bundle (only one extension deployed). Use the root-level wrapper to run the installer from this repository when promoting fixes.
- Legacy callers of `/webauthn/*` should be routed by reverse proxy (e.g., nginx rewrite) to `/webauthn/*` until clients are updated.
- Health endpoint lives at the extension root (`GET /webauthn/`) and should return `{ status: "ok" }` with rpId/origin details.
- ReactApp2 defaults to `/webauthn`; override with `REACT_APP_WEBAUTHN_BASE` only when explicitly pointed at a non-standard mount.
- Deployment validation: Directus logs should include the single WebAuthn extension (`... webauthn ...`). Run `scripts/test-webauthn-routes.sh <DIRECTUS_BASE_URL>` to probe the canonical base after deploy.

## Rollback
1. Restore the previous extension build and `env file` values.
2. Clear stale challenge rows from `webauthn_challenges` if verification loops are blocked.
3. Verify `/webauthn/registration/options` and `/authentication/options` respond with the prior behavior before allowing user logins.
