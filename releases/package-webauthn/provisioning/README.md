# Provisioning (Directus 11 + WebAuthn)

These scripts install Directus 11 prerequisites and provision the WebAuthn collections.

## Install Directus 11 CLI

```bash
./install_directus_11.sh --mode dev
```

Optional initialization:

```bash
./install_directus_11.sh --mode dev --init --project-path ./directus-11
```

## Provision WebAuthn collections

Ensure the Directus API URL and token environment variables are exported before running.

```bash
./provision_webauthn_collections.sh --mode dev
```

To sync fields from DEV while provisioning PROD (requires explicit dev env path):

```bash
./provision_webauthn_collections.sh --mode prod --sync-from-dev --dev-env-path /path/to/dev-env
```
