# WebAuthn endpoint (canonical)

This Directus endpoint extension exposes the WebAuthn API under the canonical `/webauthn` base path while delegating route handling to the shared `webauthn-router-shared` package.

## Configuration

The router resolves runtime configuration from `process.env` and optionally from env files listed in `WEBAUTHN_ENV_PATHS`/`WEBAUTHN_ENV_FILE`. Missing optional files are only logged once per process. When `WEBAUTHN_MODE=dev`, the router can derive `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGINS` from the incoming request if absent to avoid opaque 500s during local development. When `WEBAUTHN_MODE=prod`, always set `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, and `WEBAUTHN_ORIGINS` explicitly.

Health is exposed at `GET /webauthn/`; DEV responses include a sanitized summary (`rpId`, origin count, userVerification) while PROD returns `{ ok: true }`.
