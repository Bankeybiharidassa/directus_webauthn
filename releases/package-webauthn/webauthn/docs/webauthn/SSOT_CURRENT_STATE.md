# WebAuthn Extension — Current State

## Locations
- **Endpoint entrypoint:** `extensions/endpoints/webauthn/src/index.ts` (compiled to `dist/index.js`).
- **Shared router logic:** `extensions/endpoints/_shared/webauthn-router/index.ts` with helpers in `env.ts`, `exceptions.ts`, and `utils.ts` (compiled to `dist/` and referenced via `main: ./dist/index.js`).
- **Package metadata:** `extensions/endpoints/webauthn/package.json` (depends only on the shared router package).

## Exposed endpoints (mounted at `/webauthn`)
- `GET /` – health summary (reports config availability, storage availability, version).
- `POST /registration/options`
- `POST /registration/verify`
- `POST /authentication/options`
- `POST /authentication/verify`
- `POST /login/start` (alias of authentication options)
- `POST /login/finish` (alias of authentication verify)
- `POST /drytest/options` (dry-run assertion options)
- `POST /drytest/verify` (dry-run assertion verify)
- `POST /otp/options` (alias of dry-run options)
- `POST /otp/verify` (alias of dry-run verify)
- `GET /credentials` and `GET /credentials/` (list stored credentials for the authenticated user)
- `DELETE /credentials/:id` (delete a credential owned by the authenticated user)

### Behaviour notes
- `/authentication/options` (and `/login/start`) accept `username`, `email`, or `identifier` for logged-out flows; when a session exists the username is inferred from `accountability.user`.

## Configuration resolution
- Primary source: `processenv file` merged with the Directus extension `baseEnv` (injected via `ApiExtensionContext`).
- Optional host-mapped env files: the loader checks `WEBAUTHN_ENV_PATHS`/`WEBAUTHN_ENV_FILE`; if none are provided it probes standard host locations (DEV: `/home/directus/dev/kibana2directus/env file`, `/directus/dev/kibana2directus/env file`, `<ENV_FILE_PATH>`; PROD: `<ENV_FILE_PATH>`, `/directus/env file`, `<ENV_FILE_PATH>`). Missing files are logged once per host but do not block startup.
- Computed defaults (when env keys are absent):
  - `WEBAUTHN_RP_ID` ← `req.hostname` (port stripped).
  - `WEBAUTHN_RP_NAME` ← `rpId`.
  - `WEBAUTHN_ORIGIN` ← `https://<hostname>`.
  - `WEBAUTHN_STORAGE_COLLECTION` ← `webauthn_credentials`.
  - `WEBAUTHN_TIMEOUT_MS` ← `60000`.
  - `WEBAUTHN_USER_VERIFICATION` ← `preferred`.
- Validation: if `rpId`, `rpName`, or `origin` remain empty after defaults, the request receives `{ ok:false, error:"webauthn_not_configured", details:{ missing:[...] } }` with HTTP 503.

## Storage collections
- Credentials: defaults to `webauthn_credentials` (override via `WEBAUTHN_STORAGE_COLLECTION`).
- Challenges: stored in `webauthn_challenges` with per-request challenges, origins, rpId, and attempt IDs.

## Logging behaviour
- DEV (`WEBAUTHN_MODE=dev` or `NODE_WEBAUTHN_MODE=development`): detailed logs with request ID, route, hostname/rpId, missing env keys, and sanitized payload metadata; stack traces exposed only in responses where appropriate.
- PROD: minimal logs containing request ID, route, and stable error code only.
