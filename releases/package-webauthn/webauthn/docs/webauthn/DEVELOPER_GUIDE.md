# WebAuthn Developer Guide (Standalone Release)

This guide documents how to use the WebAuthn release package as a clean, standalone project. It covers project structure, build/test commands, environment rules, and operational caveats.

## Goals for a clean standalone repo

- **No hard-coded secrets**: All credentials are read from env vars or env files only. Never commit live tokens, cookies, or usernames.
- **No hard-coded servers**: Use placeholders (`<DIRECTUS_BASE_URL>`) and env variables for real hosts.
- **Deterministic packaging**: Build artifacts should be generated from source and included in the release package where required.

## Repository layout (release package)

```
webauthn/
  docs/webauthn/               # Documentation (contracts, procedures, verification)
  extensions/endpoints/        # Directus endpoint extensions
    _shared/webauthn-router/   # Shared router package (source + dist)
    webauthn/                  # Canonical WebAuthn endpoint
  tools/                       # Operational utilities (schema, diagnostics, replay)
  install_webauthn_extension.sh
```

### Key components

- **Shared router**: `extensions/endpoints/_shared/webauthn-router`
  - Source: `*.ts`
  - Build output: `dist/*.js` + `dist/*.d.ts`
- **Endpoint extension**: `extensions/endpoints/webauthn`
  - Uses the shared router via `file:../_shared/webauthn-router`
- **Operational tools**: `tools/` and `tools/webauthn/`

## Environment and secrets

### SSOT-compliant variables

Use these names only. They map to the SSOT requirements in this repo:

- **DEV base URL**: `DIRECTUS_URL_DEV` (or `DIRECTUS_API_DEV`, `DIRECTUS_BASE_URL_DEV`, `APP_BASE_URL_DEV`, `PUBLIC_URL_DEV`)
- **PROD base URL**: `DIRECTUS_URL` (or `DIRECTUS_API`, `DIRECTUS_BASE_URL`, `APP_BASE_URL`, `PUBLIC_URL`)
- **DEV token**: `DIRECTUS_TOKEN_DEV` (or `DIRECTUS_DEMO_TOKEN_DEV`)
- **PROD token**: `DIRECTUS_TOKEN` (or `DIRECTUS_API_TOKEN`)

### Mode rules

- Use explicit mode flags: `--mode dev` or `--mode prod`.
- DEV mode reads `./.env` only.
- PROD mode reads `/home/directus/.env` only.

### Secrets hygiene

- Never print tokens in logs or commit them in fixtures.
- Redact tokens/cookies in HAR files before storing under `tools/webauthn/fixtures/`.
- Use placeholders in docs (`<DIRECTUS_BASE_URL>`).

## Build and test

### Install dependencies

```bash
npm install --prefix extensions/endpoints/_shared/webauthn-router
npm install --prefix extensions/endpoints/webauthn
```

### Build shared router

```bash
npm --prefix extensions/endpoints/_shared/webauthn-router run build
```

### Build the endpoint extension

```bash
npm --prefix extensions/endpoints/webauthn run build
```

### Run unit/integration tests

```bash
npm --prefix extensions/endpoints/webauthn test
```

> Note: the test suite expects WebAuthn collections (`webauthn_credentials`, `webauthn_challenges`) to exist in the Directus schema. If these are missing, tests that exercise storage will fail with `webauthn_storage_schema_invalid`.

## Operational scripts and checks

### Validate storage schema

```bash
python tools/provision_webauthn_storage_directus.py --mode dev
python tools/verify_webauthn_storage_contract.py --mode dev
```

### Smoke tests (DEV)

```bash
./tools/webauthn/curl_smoke_tests.sh --mode dev
./tools/webauthn_acceptance_tests.sh --mode dev
```

### Replay/diagnostics toolkit

See `tools/webauthn/README.md` for HAR-based replay commands and diagnostics.

## Release packaging checklist

1. **Run builds** for `_shared/webauthn-router` and `extensions/endpoints/webauthn`.
2. **Verify dist artifacts** exist under `_shared/webauthn-router/dist`.
3. **Run tests** (or document why they were skipped and any failures).
4. **Update build logs** under `build_logs/` with timestamp, files changed, and tests run.
5. **Re-audit docs** to ensure no credentials or hard-coded server URLs were introduced.

## Security and compliance caveats

- Token mapping is strict: `DIRECTUS_TOKEN` is for your production server and `DIRECTUS_TOKEN_DEV` is for your dev server.
- WebAuthn storage collections must validate against the contract in `docs/webauthn/storage_contract.json`.
- Do not use JSON ingestion for unrelated pipelines (this repo is XML-only for Elastic → Directus flows).

## Troubleshooting tips

- **Missing storage**: run the provisioning script and re-check `webauthn_credentials`/`webauthn_challenges`.
- **CORS/Origin mismatch**: ensure `WEBAUTHN_RP_ID` matches host and `WEBAUTHN_ORIGINS` includes the full origin.
- **Stale build info**: re-run the shared router build to refresh `dist/build_info.json`.

## Standalone transfer notes

When moving to a clean repository:

- Copy the `webauthn/` release directory as the new repo root.
- Recreate `build_logs/` or replace it with your own change log policy.
- Update `git_repo` headers in scripts if the canonical URL changes.
- Re-run `npm install` and `npm run build` for both shared and endpoint packages.
