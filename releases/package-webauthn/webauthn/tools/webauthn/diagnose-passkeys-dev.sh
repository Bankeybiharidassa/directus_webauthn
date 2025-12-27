#!/usr/bin/env bash
# file: tools/webauthn/diagnose-passkeys-dev.sh
# purpose: quick DEV WebAuthn diagnostics (contract wrapper, rp/rpId presence, credential counts)
# version: 1.0.1
# mode: DEV

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ./tools/webauthn/diagnose-passkeys-dev.sh --mode dev --email <user@example.com> [--token <token>] [--base <url>]

Required:
  --mode|-m    dev|prod (explicit per SSOT)
  --email      email/identifier used for register/login starts

Optional:
  --token      Directus static token (defaults: DIRECTUS_TOKEN_DEV for dev, DIRECTUS_TOKEN for prod)
  --base       Override API base URL (defaults: DIRECTUS_URL_DEV or DIRECTUS_URL)
  --help       Show this message

The script probes /webauthn-auth health, register/login/drytest start wrappers, credential listing, and (DEV only) /debug/credentials.
USAGE
}

MODE=""
EMAIL=""
TOKEN=""
BASE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode)
      MODE="${2:-}"
      shift 2
      ;;
    --email)
      EMAIL="${2:-}"
      shift 2
      ;;
    --token)
      TOKEN="${2:-}"
      shift 2
      ;;
    --base)
      BASE="${2:-}"
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
  echo "--mode is required (dev|prod)" >&2
  usage
  exit 1
fi

if [[ "$MODE" != "dev" && "$MODE" != "prod" ]]; then
  echo "--mode must be dev or prod" >&2
  exit 1
fi

if [[ -z "$EMAIL" ]]; then
  echo "--email is required" >&2
  exit 1
fi

if [[ -z "$TOKEN" ]]; then
  if [[ "$MODE" == "dev" ]]; then
    TOKEN=${DIRECTUS_TOKEN_DEV:-}
  else
    TOKEN=${DIRECTUS_TOKEN:-}
  fi
fi

if [[ -z "$TOKEN" ]]; then
  echo "Directus token is required (set --token or DIRECTUS_TOKEN_DEV/DIRECTUS_TOKEN)" >&2
  exit 1
fi

if [[ -z "$BASE" ]]; then
  if [[ "$MODE" == "dev" ]]; then
    BASE=${DIRECTUS_URL_DEV:-}
  else
    BASE=${DIRECTUS_URL:-}
  fi
fi

if [[ -z "$BASE" ]]; then
  echo "Directus base URL is required (set --base or DIRECTUS_URL[_DEV])" >&2
  exit 1
fi

AUTH_HEADER=("-H" "Authorization: Bearer $TOKEN")
CT_HEADER=("-H" "Content-Type: application/json")

jq_present() {
  command -v jq >/dev/null 2>&1
}

pretty() {
  if jq_present; then
    jq -r "$1"
  else
    cat
  fi
}

echo "[webauthn][probe] mode=$MODE base=$BASE"

curl -sS "${AUTH_HEADER[@]}" "$BASE/webauthn-auth/" | pretty '. | {status, mode, envPath: .envPath}'

curl -sS "${AUTH_HEADER[@]}" "${CT_HEADER[@]}" -X POST "$BASE/webauthn-auth/register/start" \
  -d "{\"email\":\"$EMAIL\"}" | pretty '{rp:.publicKey.rp, user:.publicKey.user.id, mode}'

curl -sS "${AUTH_HEADER[@]}" "${CT_HEADER[@]}" -X POST "$BASE/webauthn-auth/login/start" \
  -d "{\"identifier\":\"$EMAIL\",\"email\":\"$EMAIL\"}" | pretty '{rpId:.publicKey.rpId, challenge:.publicKey.challenge, loginAttemptId}'

curl -sS "${AUTH_HEADER[@]}" "${CT_HEADER[@]}" -X POST "$BASE/webauthn-auth/drytest/options" \
  -d '{}' | pretty '{rpId:.publicKey.rpId, challenge:.publicKey.challenge, dryTestAttemptId}'

curl -sS "${AUTH_HEADER[@]}" "$BASE/webauthn-auth/credentials" | pretty '{count: (.credentials|length), sample: (.credentials[0]//null)}'

if [[ "$MODE" == "dev" ]]; then
  curl -sS "${AUTH_HEADER[@]}" "$BASE/webauthn-auth/debug/credentials" | pretty '{me_id, total_credentials_count, my_credentials_count, sample}'
else
  echo "[webauthn][probe] skipping /debug/credentials in prod"
fi
