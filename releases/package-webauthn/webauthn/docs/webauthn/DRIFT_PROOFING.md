# Drift Proofing

To prevent ambiguous deployments, the WebAuthn extension now exposes explicit build and routing fingerprints.

## Runtime headers

- Every WebAuthn response includes `X-WebAuthn-Extension-Build: <git_sha>`.
- Use this header to confirm which commit is serving requests.

## Health payload

`GET /webauthn/health` returns:

- `build.git_sha`, `build.branch`, `build.build_time`, `build.package_version`
- Storage diagnostics when enabled (schema version, missing collections/fields)

## Verification steps

1. Call `/webauthn/health` and verify the build block matches the expected commit/branch.
2. Confirm `storage.available` is `true` and `collections` point to `webauthn_credentials` and `webauthn_challenges`.
3. For mismatches, run `tools/provision_webauthn_storage.ts` and redeploy the correct build.
