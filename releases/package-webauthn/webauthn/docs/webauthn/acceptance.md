# file: docs/webauthn/acceptance.md
# purpose: WebAuthn acceptance evidence (DEV)
# version: 1.0.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: DEV
# last_reviewed_by: codex
# last_reviewed_at: 2025-12-16

## Checklist

- PASS — TypeScript build covers DOM/import-assertion paths for ReactApp2 (`npm run build` in `reactapp2`).
- PASS — Extension unit tests for WebAuthn options (`npx vitest run extensions/endpoints/webauthn/src/__tests__/register-options.test.ts`).
- PENDING — Live DEV dry-test: `/webauthn/drytest/options` → `/webauthn/drytest/verify` with a registered credential.
- PENDING — Live DEV login verify: `/webauthn/login/start` → `/webauthn/login/finish` yields authenticated session.
