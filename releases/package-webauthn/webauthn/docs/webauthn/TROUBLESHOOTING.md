# WebAuthn Troubleshooting

- Confirm `WEBAUTHN_RP_ID` matches the hostname and each entry in `WEBAUTHN_ORIGINS` matches `window.location.origin` exactly.
- Clear stale rows from `webauthn_challenges` if ceremonies fail due to expired or reused challenges.
- Ensure `webauthn_credentials` rows store base64url `credential_id` values; malformed IDs will be skipped when building `allowCredentials`.
