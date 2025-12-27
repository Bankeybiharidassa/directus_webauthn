#!/usr/bin/env bash
# file: tools/webauthn/diagnostics/collect_webauthn_credentials_shape.sh
# purpose: Collect DEV WebAuthn credential shapes for diagnostics
# version: 1.0.2
# git_commit: <pending>
# git_repo: https://github.com/openaiproxy/kibana2directus
# mode: DEV
# last_reviewed_by: codex

set -euo pipefail

BASE_URL=${DIRECTUS_URL_DEV:-${DIRECTUS_URL:-""}}
TOKEN=${DIRECTUS_TOKEN_DEV:-${DIRECTUS_DEMO_TOKEN_DEV:-""}}
OUT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
REPORT="$OUT_DIR/webauthn_credentials_shape.json"

if [[ -z "$BASE_URL" ]]; then
  echo "DIRECTUS_URL_DEV (or DIRECTUS_URL) is required" >&2
  exit 1
fi

if [[ -z "$TOKEN" ]]; then
  echo "DIRECTUS_TOKEN_DEV (or DIRECTUS_DEMO_TOKEN_DEV) is required" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

call() {
  local path="$1"
  shift
  curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL$path" "$@"
}

FIELDS_QUERY="?limit=25&fields=id,user,credential_id,public_key,sign_count,transports,nickname,created_at,last_used_at"

FIELDS_OUTPUT=$(call "/fields/webauthn_credentials")
COLLECTION_OUTPUT=$(call "/collections/webauthn_credentials")
SAMPLE_OUTPUT=$(call "/items/webauthn_credentials$FIELDS_QUERY")

jq -n \
  --arg base_url "$BASE_URL" \
  --arg timestamp "$(date --iso-8601=seconds)" \
  --argjson fields "$FIELDS_OUTPUT" \
  --argjson collection "$COLLECTION_OUTPUT" \
  --argjson sample "$SAMPLE_OUTPUT" \
  '{
    collected_at: $timestamp,
    base_url: $base_url,
    fields: $fields,
    collection: $collection,
    sample: $sample
  }' > "$REPORT"

echo "Wrote $REPORT"
