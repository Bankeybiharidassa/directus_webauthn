#!/usr/bin/env bash
# file: tools/webauthn/curl_smoke_tests.sh
# purpose: curl-based WebAuthn smoke for register/login options (DEV or PROD) using live Directus endpoints
# version: 1.2.1
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex
# last_reviewed_at: 2026-01-17

set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 --mode <dev|prod> --email <user_email> [--env-path <path>]

Performs four checks against live Directus endpoints:
  1) GET /webauthn/ health (expects HTTP 200)
  2) POST /webauthn/login/start returns publicKey.challenge + publicKey.rpId
  3) POST /webauthn/registration/options returns publicKey.challenge + publicKey.rp + publicKey.user
  4) GET /webauthn/credentials returns ok:true (empty list acceptable)

Requirements:
  - Directus tokens in the environment or env file (DEV: DIRECTUS_TOKEN_DEV, PROD: DIRECTUS_TOKEN).
  - Base URL variables per SSOT (DEV: DIRECTUS_URL_DEV/DIRECTUS_API_DEV/..., PROD: DIRECTUS_URL/DIRECTUS_API/...).

If any step fails or returns 500, the script prints the response body and exits non-zero.
USAGE
  exit 1
}

MODE=""
EMAIL=""
ENV_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode|-m)
      MODE="$2"
      shift 2
      ;;
    --email)
      EMAIL="$2"
      shift 2
      ;;
    --env-path)
      ENV_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

[[ -z "$MODE" || -z "$EMAIL" ]] && usage
if [[ "$MODE" != "dev" && "$MODE" != "prod" ]]; then
  echo "Mode must be dev or prod" >&2
  exit 1
fi

if [[ -n "$ENV_PATH" ]]; then
  if [[ ! -f "$ENV_PATH" ]]; then
    echo "Env file not found: $ENV_PATH" >&2
    exit 1
  fi
  set -a
  source "$ENV_PATH"
  set +a
fi

pick_var() {
  for key in "$@"; do
    local val="${!key:-}"
    if [[ -n "$val" ]]; then
      echo "$val"
      return 0
    fi
  done
  return 1
}

if [[ "$MODE" == "dev" ]]; then
  TOKEN="$(pick_var DIRECTUS_TOKEN_DEV DIRECTUS_DEMO_TOKEN_DEV)"
  BASE_URL="$(pick_var DIRECTUS_URL_DEV DIRECTUS_API_DEV DIRECTUS_BASE_URL_DEV APP_BASE_URL_DEV PUBLIC_URL_DEV)"
else
  TOKEN="$(pick_var DIRECTUS_TOKEN DIRECTUS_API_TOKEN)"
  BASE_URL="$(pick_var DIRECTUS_URL DIRECTUS_API DIRECTUS_BASE_URL APP_BASE_URL PUBLIC_URL)"
fi

if [[ -z "$TOKEN" || -z "$BASE_URL" ]]; then
  echo "Missing Directus token or base URL for mode=$MODE" >&2
  exit 1
fi

BASE_URL="${BASE_URL%/}"
TMP_HEALTH=$(mktemp)
TMP_AUTH=$(mktemp)
TMP_REG=$(mktemp)
TMP_CREDS=$(mktemp)
cleanup() { rm -f "$TMP_HEALTH" "$TMP_AUTH" "$TMP_REG" "$TMP_CREDS"; }
trap cleanup EXIT

request() {
  local method="$1" path="$2" body="$3" outfile="$4"
  if [[ -n "$body" ]]; then
    curl -sS -o "$outfile" -w "%{http_code}" -X "$method" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "$body" \
      "$BASE_URL$path"
  else
    curl -sS -o "$outfile" -w "%{http_code}" -X "$method" \
      -H "Authorization: Bearer $TOKEN" \
      "$BASE_URL$path"
  fi
}

assert_public_key_fields() {
  local file="$1" label="$2"
  local challenge rp_id
  challenge=$(jq -r '.data.publicKey.challenge // empty' "$file")
  rp_id=$(jq -r '.data.publicKey.rpId // .data.publicKey.rpID // empty' "$file")

  if [[ -z "$challenge" || -z "$rp_id" ]]; then
    echo "${label}: server response missing publicKey.challenge or rpId" >&2
    cat "$file" >&2
    exit 1
  fi
}

assert_registration_fields() {
  local file="$1"
  local user rp
  user=$(jq -r '.data.publicKey.user.id // empty' "$file")
  rp=$(jq -r '.data.publicKey.rp.id // empty' "$file")

  if [[ -z "$user" || -z "$rp" ]]; then
    echo "registration/options: missing publicKey.user.id or publicKey.rp.id" >&2
    cat "$file" >&2
    exit 1
  fi
}

echo "[1/4] GET /webauthn/ health"
HEALTH_STATUS=$(request GET "/webauthn/" "" "$TMP_HEALTH")
if [[ "$HEALTH_STATUS" != "200" ]]; then
  echo "Health check failed with status $HEALTH_STATUS" >&2
  cat "$TMP_HEALTH" >&2
  exit 1
fi
jq '{ok, version: .data.version, configAvailable: .data.config.available, storageAvailable: .data.storage.available}' "$TMP_HEALTH"

echo "[2/4] POST /webauthn/login/start"
AUTH_STATUS=$(request POST "/webauthn/login/start" "{\"email\":\"$EMAIL\",\"identifier\":\"$EMAIL\"}" "$TMP_AUTH")
if [[ "$AUTH_STATUS" != "200" ]]; then
  echo "Authentication options failed with status $AUTH_STATUS" >&2
  cat "$TMP_AUTH" >&2
  exit 1
fi
assert_public_key_fields "$TMP_AUTH" "authentication/options"
jq '{challenge: .data.publicKey.challenge|tostring|length, rpId: .data.publicKey.rpId}' "$TMP_AUTH"

echo "[3/4] POST /webauthn/registration/options"
REG_STATUS=$(request POST "/webauthn/registration/options" "{\"email\":\"$EMAIL\",\"identifier\":\"$EMAIL\"}" "$TMP_REG")
if [[ "$REG_STATUS" != "200" ]]; then
  echo "Registration options failed with status $REG_STATUS" >&2
  cat "$TMP_REG" >&2
  exit 1
fi
assert_public_key_fields "$TMP_REG" "registration/options"
assert_registration_fields "$TMP_REG"
jq '{challenge: .data.publicKey.challenge|tostring|length, rpId: .data.publicKey.rpId, userId: .data.publicKey.user.id}' "$TMP_REG"

echo "[4/4] GET /webauthn/credentials"
CREDS_STATUS=$(request GET "/webauthn/credentials" "" "$TMP_CREDS")
if [[ "$CREDS_STATUS" != "200" ]]; then
  echo "Credentials listing failed with status $CREDS_STATUS" >&2
  cat "$TMP_CREDS" >&2
  exit 1
fi
ok_flag=$(jq -r '.ok // empty' "$TMP_CREDS")
if [[ "$ok_flag" != "true" ]]; then
  echo "Credentials endpoint did not return ok:true" >&2
  cat "$TMP_CREDS" >&2
  exit 1
fi
jq '{credentialsCount: (.credentials|length // 0)}' "$TMP_CREDS"
