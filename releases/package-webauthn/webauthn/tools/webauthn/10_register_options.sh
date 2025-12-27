#!/usr/bin/env bash
set -euo pipefail

DIRECTUS_URL="${DIRECTUS_URL_DEV:-${DIRECTUS_URL:-}}"
TOKEN="${DIRECTUS_TOKEN_DEV:-}"
EMAIL="${WEBAUTHN_EMAIL:-}"

if [[ -z "$DIRECTUS_URL" ]]; then
  echo "DIRECTUS_URL_DEV (or DIRECTUS_URL) is required." >&2
  exit 1
fi

if [[ -z "$TOKEN" || -z "$EMAIL" ]]; then
  echo "DIRECTUS_TOKEN_DEV and WEBAUTHN_EMAIL are required." >&2
  exit 1
fi

BODY=$(jq -cn --arg email "$EMAIL" '{email: $email}')
echo "[webauthn][register/options] POST ${DIRECTUS_URL}/webauthn-auth/register/start email=${EMAIL}"
RAW=$(curl -sS -f \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  -d "${BODY}" \
  "${DIRECTUS_URL}/webauthn-auth/register/start")

echo "${RAW}" | node -e "const data=JSON.parse(require('fs').readFileSync(0,'utf8')); if(!data?.options?.rp?.id || !data?.options?.rp?.name){console.error('Missing rp in response'); process.exit(1);} console.log('rp', data.options.rp, 'challengeLength', (data.options.publicKey?.challenge || data.options.challenge || '').length);"
