#!/usr/bin/env bash
set -euo pipefail

MODE="dev"
ENV_PATH=""
BASE_URL=""
TOKEN=""
USER_ID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode|-m)
      MODE="$2"; shift 2;;
    --env-path)
      ENV_PATH="$2"; shift 2;;
    --base-url)
      BASE_URL="$2"; shift 2;;
    --token)
      TOKEN="$2"; shift 2;;
    --user-id)
      USER_ID="$2"; shift 2;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for verification" >&2
  exit 1
fi

if [[ -z "$BASE_URL" || -z "$TOKEN" ]]; then
  if [[ -n "$ENV_PATH" ]]; then
    if [[ ! -f "$ENV_PATH" ]]; then
      echo "Env file not found: $ENV_PATH" >&2
      exit 1
    fi
    set -o allexport
    # shellcheck disable=SC1090
    source "$ENV_PATH"
    set +o allexport
  fi

  if [[ -z "$BASE_URL" ]]; then
    if [[ "$MODE" == "dev" ]]; then
      BASE_URL=${DIRECTUS_URL_DEV:-${DIRECTUS_API_DEV:-${DIRECTUS_BASE_URL_DEV:-${APP_BASE_URL_DEV:-${PUBLIC_URL_DEV:-""}}}}}
    else
      BASE_URL=${DIRECTUS_URL:-${DIRECTUS_API:-${DIRECTUS_BASE_URL:-${APP_BASE_URL:-${PUBLIC_URL:-""}}}}}
    fi
  fi
  if [[ -z "$TOKEN" ]]; then
    if [[ "$MODE" == "dev" ]]; then
      TOKEN=${DIRECTUS_TOKEN_DEV:-${DIRECTUS_DEMO_TOKEN_DEV:-""}}
    else
      TOKEN=${DIRECTUS_TOKEN:-${DIRECTUS_API_TOKEN:-""}}
    fi
  fi
fi

if [[ -z "$BASE_URL" || -z "$TOKEN" ]]; then
  echo "Base URL or token missing after env resolution" >&2
  exit 1
fi

BASE_URL=${BASE_URL%/}

STATUS=0
BODY=""

api_request() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local tmp
  tmp=$(mktemp)
  if [[ -n "$data" ]]; then
    STATUS=$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      "$BASE_URL/$path" \
      -d "$data")
  else
    STATUS=$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer $TOKEN" \
      "$BASE_URL/$path")
  fi
  BODY=$(cat "$tmp")
  rm -f "$tmp"
  if [[ "$STATUS" -ge 400 ]]; then
    echo "API request failed ($method $path -> $STATUS): $BODY" >&2
    exit 1
  fi
}

require_uuid_field() {
  local collection="$1"
  api_request GET "fields/${collection}/id"
  local data
  data=$(echo "$BODY" | jq -r '.data // .')
  local dtype
  dtype=$(echo "$data" | jq -r '(.schema.data_type // .type // "") | ascii_downcase')
  local is_pk
  is_pk=$(echo "$data" | jq -r '(.schema.is_primary_key // false)')
  if [[ "$dtype" != "uuid" || "$is_pk" != "true" ]]; then
    echo "${collection}.id is ${dtype:-unknown} (primary=$is_pk); expected uuid primary key" >&2
    exit 1
  fi
}

if [[ -z "$USER_ID" ]]; then
  api_request GET "users/me"
  USER_ID=$(echo "$BODY" | jq -r '.data.id // empty')
  if [[ -z "$USER_ID" ]]; then
    echo "Unable to resolve user id from /users/me; provide --user-id" >&2
    exit 1
  fi
fi

require_uuid_field "webauthn_credentials"
require_uuid_field "webauthn_challenges"

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EXPIRES=$(date -u -d '+5 minutes' +%Y-%m-%dT%H:%M:%SZ)

auto_challenge_payload=$(jq -n \
  --arg user "$USER_ID" \
  --arg challenge "autogen-$$" \
  --arg expires "$EXPIRES" \
  --arg created "$NOW" \
  '({
    user: $user,
    challenge: $challenge,
    type: "registration",
    expires_at: $expires,
    created_at: $created,
    used_at: null,
    rp_id: "verify-script",
    origin: "https://verify-script.local"
  })')

api_request POST "items/webauthn_challenges" "$auto_challenge_payload"
AUTO_ATTEMPT_ID=$(echo "$BODY" | jq -r '.data.id // .id // empty')
if [[ -z "$AUTO_ATTEMPT_ID" ]]; then
  echo "Auto-generated challenge id missing from response" >&2
  exit 1
fi
if [[ ! "$AUTO_ATTEMPT_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  echo "Auto-generated challenge id is not a UUID: $AUTO_ATTEMPT_ID" >&2
  exit 1
fi
api_request GET "items/webauthn_challenges/$AUTO_ATTEMPT_ID"

ATTEMPT_ID=$(uuidgen)
CRED_ID=$(uuidgen)
CRED_KEY=$(uuidgen | tr -d '-')

challenge_payload=$(jq -n \
  --arg id "$ATTEMPT_ID" \
  --arg user "$USER_ID" \
  --arg challenge "verification-$ATTEMPT_ID" \
  --arg expires "$EXPIRES" \
  --arg created "$NOW" \
  '({
    id: $id,
    user: $user,
    challenge: $challenge,
    type: "registration",
    expires_at: $expires,
    created_at: $created,
    used_at: null,
    rp_id: "verify-script",
    origin: "https://verify-script.local"
  })')

api_request POST "items/webauthn_challenges" "$challenge_payload"
api_request GET "items/webauthn_challenges/$ATTEMPT_ID"

api_request PATCH "items/webauthn_challenges/$ATTEMPT_ID" \
  "{\"used_at\": \"$NOW\"}"

AUTO_CRED_KEY=$(uuidgen | tr -d '-')
auto_cred_payload=$(jq -n \
  --arg user "$USER_ID" \
  --arg cid "$AUTO_CRED_KEY" \
  --arg now "$NOW" \
  '({
    user: $user,
    credential_id: $cid,
    public_key: "dGVzdF9wdWJsaWNfa2V5",
    sign_count: 0,
    transports: [],
    aaguid: null,
    device_type: "platform",
    backed_up: false,
    nickname: "webauthn-storage-autogen",
    user_agent: "storage-verifier",
    origin: "https://verify-script.local",
    created_at: $now,
    updated_at: $now,
    last_used_at: null
  })')

api_request POST "items/webauthn_credentials" "$auto_cred_payload"
AUTO_CRED_ID=$(echo "$BODY" | jq -r '.data.id // .id // empty')
if [[ -z "$AUTO_CRED_ID" ]]; then
  echo "Auto-generated credential id missing from response" >&2
  exit 1
fi
if [[ ! "$AUTO_CRED_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  echo "Auto-generated credential id is not a UUID: $AUTO_CRED_ID" >&2
  exit 1
fi
api_request GET "items/webauthn_credentials/$AUTO_CRED_ID"

cred_payload=$(jq -n \
  --arg id "$CRED_ID" \
  --arg user "$USER_ID" \
  --arg cid "$CRED_KEY" \
  --arg now "$NOW" \
  '({
    id: $id,
    user: $user,
    credential_id: $cid,
    public_key: "dGVzdF9wdWJsaWNfa2V5",
    sign_count: 0,
    transports: [],
    aaguid: null,
    device_type: "platform",
    backed_up: false,
    nickname: "webauthn-storage-verify",
    user_agent: "storage-verifier",
    origin: "https://verify-script.local",
    created_at: $now,
    updated_at: $now,
    last_used_at: null
  })')

api_request POST "items/webauthn_credentials" "$cred_payload"
api_request GET "items/webauthn_credentials?filter[user][_eq]=$USER_ID&limit=5"

if ! echo "$BODY" | jq -e --arg id "$CRED_ID" '.data[] | select(.id == $id)' >/dev/null; then
  echo "Inserted credential not returned by list endpoint" >&2
  exit 1
fi

# Cleanup best effort
curl -sS -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE_URL/items/webauthn_credentials/$CRED_ID" || true
curl -sS -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE_URL/items/webauthn_credentials/$AUTO_CRED_ID" || true
curl -sS -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE_URL/items/webauthn_challenges/$ATTEMPT_ID" || true
curl -sS -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE_URL/items/webauthn_challenges/$AUTO_ATTEMPT_ID" || true

echo "Storage verification succeeded (UUID PKs enforced, CRUD roundtrip ok)"
