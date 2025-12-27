#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-${DIRECTUS_URL:-http://localhost:8055}}"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

health_headers="${TMP_DIR}/health.headers"
cred_headers="${TMP_DIR}/cred.headers"
health_body="${TMP_DIR}/health.json"
cred_body="${TMP_DIR}/cred.json"

curl -sSL -D "${health_headers}" -o "${health_body}" "${BASE_URL}/webauthn/health" >/dev/null
curl -sSL -D "${cred_headers}" -o "${cred_body}" "${BASE_URL}/webauthn/credentials" >/dev/null

parse_header() {
  local file="$1" key="$2"
  awk -v key="${key}" 'BEGIN{IGNORECASE=1} tolower($1)==tolower(key ":") {print $2}' "${file}" | tr -d '\r' | head -n1
}

health_build=$(parse_header "${health_headers}" "X-WebAuthn-Build")
cred_build=$(parse_header "${cred_headers}" "X-WebAuthn-Build")

if [[ -z "${health_build}" || -z "${cred_build}" ]]; then
  echo "Missing build headers from endpoints" >&2
  exit 1
fi

if [[ "${health_build}" != "${cred_build}" ]]; then
  echo "MULTI-BACKEND or MULTI-EXTENSION MOUNT" >&2
  exit 1
fi

python - <<'PY'
import json,sys
from pathlib import Path
health = json.loads(Path('${health_body}').read_text() or '{}')
creds = json.loads(Path('${cred_body}').read_text() or '{}')
health_available = bool(health.get('data',{}).get('storage',{}).get('available'))
cred_error = (creds.get('error') or creds.get('data',{}).get('error') or creds.get('error_code'))
if health_available and cred_error and 'storage' in str(cred_error):
    sys.stderr.write('storage mismatch: health available but credentials report storage error\n')
    sys.exit(2)
PY
