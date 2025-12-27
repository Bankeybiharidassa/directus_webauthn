# WebAuthn Route Compatibility

Canonical endpoints (per SSOT):
- `GET /webauthn/health`
- `GET /webauthn/credentials`
- `POST /webauthn/registration/options`
- `POST /webauthn/registration/verify`
- `POST /webauthn/authentication/options`
- `POST /webauthn/authentication/verify`

Legacy aliases served by the same handlers:
- `POST /webauthn/login/start` → `/webauthn/authentication/options`
- `POST /webauthn/login/finish` → `/webauthn/authentication/verify`
- `POST /webauthn/drytest/options` → `/webauthn/registration/options`
- `POST /webauthn/drytest/verify` → `/webauthn/registration/verify`

Any other WebAuthn paths should be treated as drift and flagged by the audit scripts.
