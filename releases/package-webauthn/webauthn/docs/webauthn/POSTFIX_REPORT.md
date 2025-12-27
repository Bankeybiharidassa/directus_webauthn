# WebAuthn extension fixes (postfix report)

## What was broken
- Storage validation relied on user-scoped schema visibility, causing `webauthn_storage_missing` errors for operators without collection permissions.
- Provisioning and verification tools mixed DB assumptions and placeholder logic, blocking API-only rollout.
- Installer skipped permission enforcement and endpoint smoke checks, leading to usable deployments that still lacked access.

## Changes implemented
- Storage checks now use Directus `CollectionsService`/`FieldsService` under admin accountability, independent of caller permissions.
- Provisioning/verification tooling is strictly Directus-API based by default; DB verification is opt-in via `--db-verify`.
- Installer enforces WebAuthn permissions, ensures env defaults, runs provisioning, and performs API health/credential checks without DB credentials.
- Added automated audit of the requirements document to guard against drift.

## How to run acceptance
1. Deploy the extension: `tools/install_webauthn_extension.sh --mode dev --base-pattern /home/directus/extensions_b`.
2. Restart Directus, then verify health: `curl -H "Authorization: Bearer $DIRECTUS_TOKEN_DEV" "$DIRECTUS_URL_DEV/webauthn/health"`.
3. List credentials while logged in: `curl -H "Authorization: Bearer $DIRECTUS_TOKEN_DEV" "$DIRECTUS_URL_DEV/webauthn/credentials"`.
4. Verify storage contract via API: `python3 tools/verify_webauthn_storage_contract.py --mode dev --env-path env file` (add `--db-verify` only if DB access is intended).

## Troubleshooting tips
- If health reports missing collections/fields, rerun provisioning with the correct env: `python3 tools/provision_webauthn_collection.py --mode dev --env-path env file`.
- If credentials endpoints return 403, rerun permission enforcement: `python3 tools/enforce_webauthn_permissions.py --mode dev`.
- For DB-level inspections, explicitly add `--db-verify` to the verification script; default runs never require DB credentials.
