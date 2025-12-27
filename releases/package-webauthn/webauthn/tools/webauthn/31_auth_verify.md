# WebAuthn auth verify (manual)

1. Run `./tools/webauthn/30_auth_options.sh` with `WEBAUTHN_EMAIL` set to trigger `/webauthn-auth/login/start` and confirm `rpId`, challenge, and `loginAttemptId` are present.
2. From the login screen, select **Sign in with passkey**, complete the WebAuthn prompt, and ensure `/webauthn-auth/login/finish` returns 200.
3. Validate session: `/users/me` should succeed immediately after the flow; ReactApp2 should render the authenticated area without re-login prompts.
