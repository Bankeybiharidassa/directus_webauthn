# WebAuthn Environment Keys

Required:
- `WEBAUTHN_RP_ID` – relying party ID (registrable domain, no scheme).
- `WEBAUTHN_RP_NAME` – human-readable RP display name.
- `WEBAUTHN_ORIGINS` – comma-separated list of allowed origins (`https://...`).

Optional:
- `WEBAUTHN_TIMEOUT_MS` – positive integer timeout for WebAuthn ceremonies (default 60000).
- `WEBAUTHN_USER_VERIFICATION` – `preferred` (default), `required`, or `discouraged`.
- `WEBAUTHN_ENV_PATHS` / `WEBAUTHN_ENV_FILE` – comma-separated list of additional env files to merge **after** `processenv file`. Missing files trigger a single warning per process, not per-request.

Behaviour:
- Configuration is loaded from `processenv file` first. Optional env files merge on top when present.
- In `WEBAUTHN_MODE=dev`, missing `WEBAUTHN_RP_ID` or `WEBAUTHN_ORIGINS` are derived from the incoming request (`req.hostname` and `${req.protocol}://${req.get('host')}`).
- In `WEBAUTHN_MODE=prod`, required keys must be explicitly set; missing keys return `503` with the missing list.
- Errors use the `{ error: { code, message, reason?, details? } }` envelope; misconfiguration never returns a generic `500`.
