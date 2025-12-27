#!/usr/bin/env bash
# file: tools/webauthn/acceptance/acceptance_login.sh
# purpose: Run WebAuthn login acceptance checks against DEV
# version: 1.0.1
# git_commit: <pending>
# git_repo: https://github.com/openaiproxy/kibana2directus
# mode: DEV
# last_reviewed_by: codex

set -euo pipefail

BASE_URL=${DIRECTUS_URL_DEV:-${DIRECTUS_URL:-""}}
TOKEN=${DIRECTUS_TOKEN_DEV:-${DIRECTUS_DEMO_TOKEN_DEV:-""}}
EMAIL=${1:-}
OUT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
START_OUT="$OUT_DIR/login_start.json"

if [[ -z "$EMAIL" ]]; then
  echo "Usage: $0 <user email>" >&2
  exit 1
fi

if [[ -z "$BASE_URL" ]]; then
  echo "DIRECTUS_URL_DEV (or DIRECTUS_URL) is required" >&2
  exit 1
fi

if [[ -z "$TOKEN" ]]; then
  echo "DIRECTUS_TOKEN_DEV (or DIRECTUS_DEMO_TOKEN_DEV) is required" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

curl -sS -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  -d "{\"email\":\"$EMAIL\"}" \
  "$BASE_URL/webauthn-auth/login/start" | tee "$START_OUT"

echo "Saved start response to $START_OUT"

auth_json=$(cat "$START_OUT")
challenge=$(echo "$auth_json" | jq -r '.options.challenge // empty')
allow_count=$(echo "$auth_json" | jq -r '.options.allowCredentials | length // 0')

if [[ -z "$challenge" ]]; then
  echo "Missing options.challenge" >&2
  exit 1
fi

echo "challenge length=${#challenge} allowCredentials=$allow_count"

echo "Complete the assertion in a browser, then POST the response to $BASE_URL/webauthn-auth/login/finish"
