# WebAuthn Release Package

This release package contains the WebAuthn Directus endpoint sources, a React sample, and provisioning helpers for a vanilla Directus 11 deployment.

## Structure

```
releases/package-webauthn/
  webauthn/        # WebAuthn extension sources + tooling (cleaned)
  react/           # React sample code
  provisioning/    # Directus 11 + WebAuthn provisioning scripts
  sample.env       # Environment variable template (placeholders only)
```

## Quick start

1. Review `sample.env` and export the required variables in your environment or secret manager.
2. Install Directus 11 using `provisioning/install_directus_11.sh`.
3. Deploy the WebAuthn extension with `webauthn/install_webauthn_extension.sh`.
4. Provision the WebAuthn collections with `provisioning/provision_webauthn_collections.sh`.
5. Validate routes using `webauthn/tools/webauthn_canonical_login_smoke.sh`.

## Notes

- All scripts require explicit `--mode dev` or `--mode prod`.
- WebAuthn sources are copied from the canonical repository paths and sanitized to remove hard-coded hosts or env-file defaults.
- Refer to `react/README.md` for sample usage.
