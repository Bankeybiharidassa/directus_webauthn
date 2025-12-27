#!/usr/bin/env bash
# file: tools/webauthn_canonical_login_smoke.sh
# purpose: Smoke check canonical WebAuthn login endpoints against Directus
# version: 1.0.3
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex
# last_reviewed_at: 2026-03-01T03:00:00Z

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: webauthn_canonical_login_smoke.sh --mode <dev|prod> [--env-path <path>]

Runs a lightweight smoke check against /webauthn/health and
/webauthn/authentication/options using the SSOT environment variables.
USAGE
}

MODE=""
ENV_PATH=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode)
      MODE=${2:-}
      shift 2
      ;;
    --env-path)
      ENV_PATH=${2:-}
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$MODE" ]]; then
  echo "--mode is required (dev or prod)" >&2
  usage
  exit 1
fi

if [[ "$MODE" != "dev" && "$MODE" != "prod" ]]; then
  echo "Invalid mode: $MODE (expected dev or prod)" >&2
  usage
  exit 1
fi

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -n "$ENV_PATH" ]]; then
  if [[ ! -f "$ENV_PATH" ]]; then
    echo "env file not found at $ENV_PATH" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  set -a
  source "$ENV_PATH"
  set +a
fi

pick_first_env() {
  for key in "$@"; do
    local value=${!key:-}
    if [[ -n "$value" ]]; then
      echo "$value"
      return 0
    fi
  done
  return 1
}

if [[ "$MODE" == "dev" ]]; then
  BASE_URL=$(pick_first_env DIRECTUS_URL_DEV DIRECTUS_API_DEV DIRECTUS_BASE_URL_DEV APP_BASE_URL_DEV PUBLIC_URL_DEV || true)
  TOKEN=$(pick_first_env DIRECTUS_TOKEN_DEV DIRECTUS_DEMO_TOKEN_DEV || true)
else
  BASE_URL=$(pick_first_env DIRECTUS_URL DIRECTUS_API DIRECTUS_BASE_URL APP_BASE_URL PUBLIC_URL || true)
  TOKEN=$(pick_first_env DIRECTUS_TOKEN DIRECTUS_API_TOKEN || true)
fi

if [[ -z "$BASE_URL" ]]; then
  echo "Base URL not found for mode $MODE" >&2
  exit 1
fi

EMAIL=${WEBAUTHN_EMAIL:-webauthn-probe@example.com}

AUTH_HEADER=()
if [[ -n "$TOKEN" ]]; then
  AUTH_HEADER=(-H "Authorization: Bearer $TOKEN")
fi

HEALTH_URL="${BASE_URL%/}/webauthn/health"
OPTIONS_URL="${BASE_URL%/}/webauthn/authentication/options"

REPORT_DIR="$REPO_ROOT/reports"
mkdir -p "$REPORT_DIR"
HEALTH_PATH="$REPORT_DIR/webauthn_health_${MODE}.json"
OPTIONS_PATH="$REPORT_DIR/webauthn_auth_options_${MODE}.json"

curl -sS "${AUTH_HEADER[@]}" "$HEALTH_URL" > "$HEALTH_PATH"

OPTIONS_PAYLOAD=$(printf '{"email":"%s","identifier":"%s"}' "$EMAIL" "$EMAIL")
curl -sS "${AUTH_HEADER[@]}" -H "content-type: application/json" -X POST "$OPTIONS_URL" -d "$OPTIONS_PAYLOAD" > "$OPTIONS_PATH"

node <<'NODE' "$HEALTH_PATH" "$OPTIONS_PATH"
const fs = require('fs');
const health = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
if (!health?.ok) {
  throw new Error('WebAuthn health check returned ok=false');
}
const payload = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const options = payload?.data?.options || payload?.data?.publicKey || payload?.data || payload?.options || payload?.publicKey || payload;
if (!options) {
  throw new Error('Missing WebAuthn options in response');
}
const re = /^[A-Za-z0-9_-]+$/;
const challenge = options.challenge;
if (typeof challenge !== 'string' || !re.test(challenge)) {
  throw new Error('WebAuthn options missing base64url challenge');
}
if (options.user?.id && !re.test(options.user.id)) {
  throw new Error('WebAuthn options user.id is not base64url');
}
if (Array.isArray(options.allowCredentials)) {
  options.allowCredentials.forEach((cred, idx) => {
    if (!re.test(cred.id)) {
      throw new Error(`allowCredentials[${idx}].id is not base64url`);
    }
  });
}
console.log('WebAuthn canonical login smoke check OK');
NODE

echo "Artifacts saved: $HEALTH_PATH $OPTIONS_PATH"
