#!/usr/bin/env bash
set -euo pipefail

DIRECTUS_URL="${DIRECTUS_URL_DEV:-${DIRECTUS_URL:-}}"
TOKEN="${DIRECTUS_TOKEN_DEV:-}"

if [[ -z "$DIRECTUS_URL" ]]; then
  echo "DIRECTUS_URL_DEV (or DIRECTUS_URL) is required." >&2
  exit 1
fi

if [[ -z "$TOKEN" ]]; then
  echo "DIRECTUS_TOKEN_DEV is required for dry-test options." >&2
  exit 1
fi

echo "[webauthn][drytest/options] POST ${DIRECTUS_URL}/webauthn-auth/drytest/options"
RAW=$(curl -sS -f \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  -d "{}" \
  "${DIRECTUS_URL}/webauthn-auth/drytest/options")

echo "${RAW}" | node -e "const data=JSON.parse(require('fs').readFileSync(0,'utf8')); const pk=data?.options?.publicKey || data?.options || data; if(!pk?.challenge){console.error('Missing challenge in dry-test options'); process.exit(1);} console.log('rpId', pk.rpId || pk.rpID || 'n/a', 'challengeLength', (pk.challenge?.length||0), 'dryTestAttemptId', data?.dryTestAttemptId ? '<present>' : 'missing');"
