# WebAuthn register verify (manual)

1. Ensure `DIRECTUS_TOKEN_DEV` and `WEBAUTHN_EMAIL` are exported; run `./tools/webauthn/10_register_options.sh` to capture options and confirm `rp.id`/`rp.name` are present.
2. In ReactApp2 (DEV), navigate to Profile → Passkeys and click **Add passkey** with the same email.
3. Allow the browser WebAuthn prompt to complete; confirm the backend responds 200 and a new `webauthn_credentials` record appears for the user.
