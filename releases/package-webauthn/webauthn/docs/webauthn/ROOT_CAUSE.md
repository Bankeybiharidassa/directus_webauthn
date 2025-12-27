# WebAuthn 500s — Root Cause

## What failed
Two independent issues caused the observed 500s:

1. The shared router package exported TypeScript source (`main: ./index.ts`) and used JSON import assertions. In production the extension dependency was loaded as-is, so Node could not resolve the TS entrypoint and emitted generic 500s instead of the explicit `webauthn_user_required`/`webauthn_not_configured` responses.
2. The login/start client POSTed `{ email, identifier }` while the backend only honored `username`. Logged-out calls therefore hit the “user required” branch even when a valid email was supplied, leaving Reactapp with a 500 in practice due to the broken TS entrypoint.

## Fix applied
- The shared router now ships compiled JS/typings in `dist/` with `main`/`exports` pointing at `dist/index.js`, removing JSON asserts and preventing Node from loading TS directly.
- `getWebAuthnServiceOrError` still merges env and host defaults but now returns stable config errors while letting list routes bypass crypto init.
- Authentication options accept `username`/`email`/`identifier` for logged-out flows, aligning with the Reactapp2 request payload and avoiding spurious “user required” failures.

## Regression guardrails
- Dev smoke script (`tools/webauthn/smoke_dev.mjs`) validates that credentials/auth options/dry-test options return either `ok:true` or `webauthn_not_configured` with a missing list.
- Contract test (`tools/webauthn/contract_test.mjs`) asserts response shapes for the main endpoints.
- Documentation (`docs/webauthn/CONTRACT.md` and `SSOT_CURRENT_STATE.md`) codifies the required behaviour and now notes the compiled shared router footprint and email/identifier login support.
- The shared router build is committed (`dist/`), preventing runtime TS resolution regressions when deployed without a build step.
