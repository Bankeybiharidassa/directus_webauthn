# WebAuthn Compliance Checklist (SSOT: REQUIREMENTS_AND_PROCEDURES.md)

This checklist captures enforceable requirements from `docs/webauthn/REQUIREMENTS_AND_PROCEDURES.md` and maps them to implementation status. Update the status column when the codebase changes.

| Area | Requirement (source) | Status | Evidence/Notes |
| --- | --- | --- | --- |
| Routes | GET `/webauthn/health` | Verified | Implemented in shared router registration. |
| Routes | GET `/webauthn/credentials` | Verified | Implemented in shared router registration. |
| Routes | POST `/webauthn/registration/options` | Verified | Implemented in shared router registration. |
| Routes | POST `/webauthn/registration/verify` | Verified | Implemented in shared router registration. |
| Routes | POST `/webauthn/authentication/options` | Verified | Implemented in shared router registration. |
| Routes | POST `/webauthn/authentication/verify` | Verified | Implemented in shared router registration. |
| Routes | Aliases `/webauthn/login/start` + `/webauthn/login/finish` | Verified | Aliased to authentication handlers. |
| Storage | Credentials collection `webauthn_credentials` | Verified | Canonical constants enforced via `storage-names.ts`. |
| Storage | Challenges collection `webauthn_challenges` | Verified | Canonical constants enforced via `storage-names.ts`. |
| Storage fields | Credentials fields (id, user, credential_id, public_key, cose_alg, sign_count, transports, aaguid, device_type, backed_up, nickname, user_agent, origin, created_at, updated_at, last_used_at) | Verified | Enforced in compliance rules, shared storage checks, and provisioning scripts. |
| Storage fields | Challenges fields (id, user, challenge, type, expires_at, created_at, used_at, rp_id, origin) | Verified | Enforced in compliance rules and provisioning scripts. |
| Security invariants | rpIdHash/origin binding, min 16-byte challenges, TTL (~300s), single-use enforcement | Verified | Implemented in shared router validation and documented in compliance rules. |
| Encodings | Base64URL without padding for WebAuthn binary fields and exact WebAuthn JSON field names | Verified | Implemented via helpers and contract tests. |
| Request/response shapes | Options endpoints return WebAuthn `publicKey` objects; verify endpoints expect WebAuthn payloads | Verified | Covered by route handlers and integration tests. |
| Errors | `webauthn_storage_schema_invalid`, `webauthn_not_configured`, `invalid_webauthn_response`, `invalid_webauthn_credentials` | Verified | Emitted by shared router error handler per SSOT. |
| Env/config | RP_ID, RP_NAME, ORIGIN_ALLOWLIST, CHALLENGE_TTL_SECONDS, ATTESTATION, USER_VERIFICATION_DEFAULT, RESIDENT_KEY, ALLOWED_COSE_ALGS | Verified | Normalized in env helpers and referenced in compliance rules. |
| Health payload | Includes build fingerprint and storage diagnostics fields (collections, missing_collections, missing_fields_by_collection, expected_schema_version) when diagnostics allowed | Verified | Implemented in health handler and storage diagnostics helper. |
| Tooling | Provision script, verify script, audit script, compliance runner, API smoke tests | Verified | Located under `tools/` with reports emitted to `reports/`. |
| Observability | Build fingerprint header `X-WebAuthn-Extension-Build` | Verified | Set on responses by shared router. |
| Contract docs | CONTRACT + storage/diagnostics documentation | Verified | See docs in `docs/webauthn/`. |
