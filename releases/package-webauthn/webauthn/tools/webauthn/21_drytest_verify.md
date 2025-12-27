# WebAuthn dry-test verify (manual)

1. With an authenticated session in ReactApp2, run `./tools/webauthn/20_drytest_options.sh` to confirm a `dryTestAttemptId` and challenge are issued.
2. In Profile → Passkeys, click **Test my passkey** and complete the WebAuthn prompt.
3. Expect UI result:
   - Green: “Passkey verified and linked to your user.”
   - Yellow: “Passkey verified but is not linked to this user.”
   Include credential id preview, label, type, and AAGUID.
4. Backend acceptance: `/webauthn-auth/drytest/verify` responds `{ ok: true, belongsToUser: true|false }` and increments the stored counter for the credential.
