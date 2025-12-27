#!/usr/bin/env bash
set -euo pipefail

MODE="${MODE:-dev}"
DIRECTUS_URL="${DIRECTUS_URL_DEV:-${DIRECTUS_URL:-}}"
TOKEN="${DIRECTUS_TOKEN_DEV:-}"

if [[ -z "$DIRECTUS_URL" ]]; then
  echo "DIRECTUS_URL_DEV (or DIRECTUS_URL) is required to probe WebAuthn endpoints." >&2
  exit 1
fi

if [[ -z "$TOKEN" ]]; then
  echo "DIRECTUS_TOKEN_DEV is required to probe DEV WebAuthn endpoints." >&2
  exit 1
fi

echo "[webauthn][env-check] mode=${MODE} url=${DIRECTUS_URL}"
curl -sS -f -H "Authorization: Bearer ${TOKEN}" "${DIRECTUS_URL}/users/me" >/dev/null
echo "[webauthn][env-check] /users/me ok"

if [[ -n "${WEBAUTHN_EMAIL:-}" ]]; then
  echo "[webauthn][env-check] email target=${WEBAUTHN_EMAIL}"
fi
