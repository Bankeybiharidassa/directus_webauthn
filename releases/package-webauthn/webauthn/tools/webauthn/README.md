# WebAuthn Debug + Replay Toolkit

These utilities replay captured WebAuthn login ceremonies against the DEV Directus instance to reproduce and debug passkey failures without generating new assertions.

## Prerequisites

- Place the operator-provided HAR at `tools/webauthn/fixtures/directus.har` (redacted of cookies/tokens).
- Export DEV credentials (SSOT-aligned):
  - `DIRECTUS_URL_DEV` (or one of `DIRECTUS_API_DEV`, `DIRECTUS_BASE_URL_DEV`, `APP_BASE_URL_DEV`, `PUBLIC_URL_DEV`)
  - `DIRECTUS_TOKEN_DEV` (or `DIRECTUS_DEMO_TOKEN_DEV`)
- Install dependencies: `npm install` (repo root) and `npm install --prefix extensions/endpoints/webauthn`.

## Scripts

- `npm run webauthn:extract-har` — writes `fixtures/extracted_start.json` and `fixtures/extracted_finish.json` plus summaries.
- `npm run webauthn:inspect` — fetches `webauthn_credentials` and reports encoding/shape to `reports/credentials_shape.json` while highlighting matches to the extracted credential ID.
- `npm run webauthn:verify-local` — runs SimpleWebAuthn verification locally using stored credential material plus the extracted ceremony; writes `reports/verify_local.json`.
- `node --loader ts-node/esm tools/webauthn/replay/replay_http.ts` — replays the extracted finish payload against DEV HTTP endpoints (challenge mismatch expected to yield `INVALID_CREDENTIALS`, not 500).
- `npm run webauthn:confirm-extension` — probes `/webauthn-auth/login/start` (and `/webauthn/login/start` fallback) with a dummy email and records the extension build fingerprint in `reports/extension_identity.json` (requires `WEBAUTHN_DEBUG=true` on the server to expose the `build` field).

## Expected Outputs

- `tools/webauthn/reports/har_extract_summary.json` — start/finish presence.
- `tools/webauthn/reports/credentials_shape.json` — credential encoding inspection and any fixture match.
- `tools/webauthn/reports/verify_local.json` — local verification result and new counter when successful.
- `tools/webauthn/reports/http_replay.json` — status/body from live HTTP replay.
- `tools/webauthn/reports/extension_identity.json` — which endpoint responded, HTTP status, and any build fingerprint included in the JSON payload.

## Troubleshooting

- Missing HAR: ensure the redacted file exists at the fixture path.
- Missing admin token: export `DIRECTUS_TOKEN_DEV` (or `DIRECTUS_DEMO_TOKEN_DEV`).
- If `verify_local` cannot find a matching credential, re-run `webauthn:inspect` to confirm stored canonical IDs align with the captured credential id/rawId.
