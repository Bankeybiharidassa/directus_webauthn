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
echo "[webauthn][login/start] POST ${DIRECTUS_URL}/webauthn-auth/login/start email=${EMAIL}"
RAW=$(curl -sS -f \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  -d "${BODY}" \
  "${DIRECTUS_URL}/webauthn-auth/login/start")

echo "${RAW}" | node -e "const data=JSON.parse(require('fs').readFileSync(0,'utf8')); const pk=data?.options?.publicKey || data?.options || data; if(!pk?.challenge){console.error('Missing challenge in login options'); process.exit(1);} console.log('rpId', pk.rpId || pk.rpID || 'n/a', 'allowCredentials', Array.isArray(pk?.allowCredentials) ? pk.allowCredentials.length : 'n/a', 'loginAttemptId', data?.loginAttemptId ? '<present>' : 'missing');"
