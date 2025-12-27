#!/usr/bin/env bash
# file: tools/install_webauthn_extension.sh
# purpose: Install the WebAuthn Directus endpoint extensions across all Directus instances under /home/directus/extention*
# version: 1.9.1
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex
# last_reviewed_at: 2025-12-23T13:05:00Z

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: install_webauthn_extension.sh --mode <dev|prod> [--base-pattern <glob>] [--skip-build] [--pk-policy <policy>] [--env-path <path>] [--dev-env-path <path>]

Installs the WebAuthn Directus endpoint extensions into every directory matching
/home/directus/extention* (or the pattern provided via --base-pattern). The script
builds the canonical package `extensions/endpoints/webauthn` and the legacy
`extensions/endpoints/webauthn-auth`, stages their minimal payloads separately, and
rsyncs them into `webauthn` (canonical) and `webauthn-auth` (legacy alias)
directories under each target. Restart the Directus services after deployment to
load the updated extensions.

Options:
  -m, --mode          Required. Explicit deployment mode: dev or prod.
  --base-pattern      Override the target glob (default: /home/directus/extention*).
  --skip-build        Use the existing dist/ output instead of running npm ci && npm run build.
  --pk-policy         Schema handling: accept-existing (warn only) or enforce-directus-contract (patch to contract). Default: enforce-directus-contract.
  --env-path          Optional env file path to source Directus/WebAuthn variables.
  --dev-env-path      Optional env file path for DEV values when syncing from dev in prod mode.
  -h, --help          Show this message.
USAGE
}

log() {
  printf '[%s] %s\n' "$(date --utc +"%Y-%m-%dT%H:%M:%SZ")" "$*"
}

get_env_value() {
  local file="$1" key="$2"
  if [[ ! -f "$file" ]]; then
    return 1
  fi

  # shellcheck disable=SC2002
  cat "$file" | grep -E "^${key}=" | tail -n 1 | sed -e "s/^${key}=//" -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

get_config_value() {
  local file="$1" key="$2"
  if [[ -n "$file" ]]; then
    get_env_value "$file" "$key" || true
  else
    local value=${!key:-}
    if [[ -n "$value" ]]; then
      echo "$value"
    fi
  fi
}

normalize_origin() {
  python3 - <<'PY' "$1"
import sys
from urllib.parse import urlparse

raw = sys.argv[1].strip()
if not raw:
    sys.exit(1)

if not raw.startswith(('http://', 'https://')):
    raw = f'https://{raw}'

parsed = urlparse(raw)
if parsed.scheme != 'https' or not parsed.hostname:
    sys.exit(1)

origin = f"{parsed.scheme}://{parsed.hostname}"
if parsed.port:
    origin = f"{origin}:{parsed.port}"

print(origin)
PY
}

derive_origin_from_env() {
  local file="$1"
  for key in PUBLIC_URL APP_BASE_URL DIRECTUS_BASE_URL DIRECTUS_URL DIRECTUS_API; do
    local value
    value=$(get_config_value "$file" "$key" || true)
    if [[ -n "$value" ]]; then
      local origin
      origin=$(normalize_origin "$value" 2>/dev/null || true)
      if [[ -n "$origin" ]]; then
        echo "$origin"
        return 0
      fi
    fi
  done
  return 1
}

ensure_env_default() {
  local file="$1" key="$2" value="$3"
  if [[ ! -f "$file" ]]; then
    return 1
  fi
  if grep -q "^${key}=" "$file"; then
    return 0
  fi
  echo "${key}=${value}" >> "$file"
  log "Added default ${key}=${value} to ${file}"
}

resolve_base_url() {
  local file="$1" mode="$2"
  local keys=(
    DIRECTUS_URL DIRECTUS_API DIRECTUS_BASE_URL APP_BASE_URL PUBLIC_URL
  )
  if [[ "$mode" == "dev" ]]; then
    keys=(DIRECTUS_URL_DEV DIRECTUS_API_DEV DIRECTUS_BASE_URL_DEV APP_BASE_URL_DEV PUBLIC_URL_DEV)
  fi

  for key in "${keys[@]}"; do
    local value
    value=$(get_config_value "$file" "$key" || true)
    if [[ -n "$value" ]]; then
      echo "$value" | sed 's:/*$::'
      return 0
    fi
  done
  return 1
}

resolve_token() {
  local file="$1" mode="$2"
  local keys=(DIRECTUS_TOKEN DIRECTUS_API_TOKEN)
  if [[ "$mode" == "dev" ]]; then
    keys=(DIRECTUS_TOKEN_DEV DIRECTUS_DEMO_TOKEN_DEV)
  fi
  for key in "${keys[@]}"; do
    local value
    value=$(get_config_value "$file" "$key" || true)
    if [[ -n "$value" ]]; then
      echo "$value"
      return 0
    fi
  done
  return 1
}

MODE=""
BASE_PATTERN=""
SKIP_BUILD=0
HAS_LEGACY=1
PK_POLICY="enforce-directus-contract"
ENV_PATH=""
DEV_ENV_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode)
      MODE=${2:-}
      shift 2
      ;;
    --base-pattern)
      BASE_PATTERN=${2:-}
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift 1
      ;;
    --pk-policy)
      PK_POLICY=${2:-}
      shift 2
      ;;
    --env-path)
      ENV_PATH=${2:-}
      shift 2
      ;;
    --dev-env-path)
      DEV_ENV_PATH=${2:-}
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
  echo "--mode is required (dev or prod)." >&2
  usage
  exit 1
fi

if [[ "$MODE" != "dev" && "$MODE" != "prod" ]]; then
  echo "Invalid mode: $MODE (expected dev or prod)." >&2
  usage
  exit 1
fi

if [[ "$PK_POLICY" != "accept-existing" && "$PK_POLICY" != "enforce-directus-contract" ]]; then
  echo "Invalid --pk-policy: $PK_POLICY (expected accept-existing or enforce-directus-contract)." >&2
  usage
  exit 1
fi

if [[ -z "$BASE_PATTERN" ]]; then
  BASE_PATTERN="/home/directus/extention*"
fi

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
EXT_CANONICAL_DIR="$REPO_ROOT/extensions/endpoints/webauthn"
EXT_LEGACY_DIR="$REPO_ROOT/extensions/endpoints/webauthn-auth"
SHARED_ROUTER_DIR="$REPO_ROOT/extensions/endpoints/_shared/webauthn-router"
PROVISION_SCRIPT="$REPO_ROOT/tools/provision_webauthn_collection.py"
VERIFY_SCRIPT="$REPO_ROOT/tools/verify_webauthn_files.sh"
CANONICAL_ENTRYPOINT="$EXT_CANONICAL_DIR/src/index.ts"
LEGACY_ENTRYPOINT="$EXT_LEGACY_DIR/src/index.ts"
SHARED_ENTRYPOINT="$SHARED_ROUTER_DIR/index.ts"
SHARED_DIST_ENTRY="$SHARED_ROUTER_DIR/dist/index.js"

if [[ ! -d "$EXT_CANONICAL_DIR" ]]; then
  echo "Canonical WebAuthn extension directory not found at $EXT_CANONICAL_DIR" >&2
  exit 1
fi

if [[ ! -d "$SHARED_ROUTER_DIR" ]]; then
  echo "Shared WebAuthn router directory not found at $SHARED_ROUTER_DIR" >&2
  exit 1
fi

if [[ ! -f "$SHARED_ENTRYPOINT" ]]; then
  echo "Shared WebAuthn router entrypoint missing at $SHARED_ENTRYPOINT" >&2
  exit 1
fi

if [[ ! -d "$EXT_LEGACY_DIR" ]]; then
  HAS_LEGACY=0
  log "Legacy WebAuthn extension directory not found at $EXT_LEGACY_DIR; skipping legacy build"
fi

if [[ ! -f "$CANONICAL_ENTRYPOINT" ]]; then
  echo "Canonical WebAuthn entrypoint missing at $CANONICAL_ENTRYPOINT" >&2
  exit 1
fi

if [[ $HAS_LEGACY -eq 1 && ! -f "$LEGACY_ENTRYPOINT" ]]; then
  HAS_LEGACY=0
  log "Legacy WebAuthn entrypoint missing at $LEGACY_ENTRYPOINT; skipping legacy build and relying on /webauthn-auth -> /webauthn proxy"
fi

if [[ ! -x "$PROVISION_SCRIPT" ]]; then
  echo "Provisioning helper not found or not executable at $PROVISION_SCRIPT" >&2
  exit 1
fi

if [[ ! -x "$VERIFY_SCRIPT" ]]; then
  echo "Verification helper not found or not executable at $VERIFY_SCRIPT" >&2
  exit 1
fi

if [[ $HAS_LEGACY -eq 1 ]]; then
  "$VERIFY_SCRIPT"
else
  "$VERIFY_SCRIPT" --allow-missing-legacy
fi

log "Starting WebAuthn extension deployment (mode=$MODE, pattern=${BASE_PATTERN:-/home/directus/extention*/webauthn}, pk-policy=$PK_POLICY)"

build_shared_router() {
  if [[ $SKIP_BUILD -eq 1 ]]; then
    if [[ -f "$SHARED_DIST_ENTRY" ]]; then
      log "Skipping shared router build; existing artifact present at $SHARED_DIST_ENTRY"
      return
    fi

    echo "Shared WebAuthn router dist missing at $SHARED_DIST_ENTRY; rerun without --skip-build" >&2
    exit 1
  fi

  log "Installing dependencies for shared WebAuthn router"
  (cd "$SHARED_ROUTER_DIR" && npm ci)
  log "Building shared WebAuthn router"
  (cd "$SHARED_ROUTER_DIR" && npm run build)

  if [[ ! -f "$SHARED_DIST_ENTRY" ]]; then
    echo "Shared WebAuthn router build failed to produce $SHARED_DIST_ENTRY" >&2
    exit 1
  fi
}

build_extension() {
  local name="$1" dir="$2" allow_missing_entrypoint=${3:-0}
  if [[ $SKIP_BUILD -eq 0 ]]; then
    log "Installing dependencies for ${name} extension"
    (cd "$dir" && npm ci)
    log "Running npm audit fix --force to remediate known vulnerabilities for ${name}"
    (cd "$dir" && npm audit fix --force)
    log "Building ${name} extension"

    if [[ $allow_missing_entrypoint -eq 1 ]]; then
      set +e
      build_output=$(cd "$dir" && npm run build 2>&1)
      build_status=$?
      set -e

      if [[ $build_status -ne 0 ]]; then
        if echo "$build_output" | grep -q "Entrypoint ./src/index.ts does not exist"; then
          HAS_LEGACY=0
          log "Legacy build skipped: source entrypoint missing. Configure /webauthn-auth -> /webauthn proxy if legacy calls remain."
        else
          echo "$build_output" >&2
          exit $build_status
        fi
      fi
    else
      (cd "$dir" && npm run build)
    fi
  else
    log "Skipping build for ${name}; using existing dist/ output"
  fi

  if [[ $HAS_LEGACY -eq 0 && $allow_missing_entrypoint -eq 1 ]]; then
    return
  fi

  if [[ ! -f "$dir/dist/index.js" ]]; then
    echo "Build artifact not found at $dir/dist/index.js" >&2
    exit 1
  fi
}

build_shared_router
build_extension "WebAuthn (canonical)" "$EXT_CANONICAL_DIR"
if [[ $HAS_LEGACY -eq 1 ]]; then
  build_extension "WebAuthn (legacy)" "$EXT_LEGACY_DIR" 1
fi

if [[ $HAS_LEGACY -eq 1 ]]; then
  "$VERIFY_SCRIPT" --require-dist
else
  "$VERIFY_SCRIPT" --require-dist --allow-missing-legacy
fi

STAGING_ROOT=$(mktemp -d)
STAGING_CANONICAL="$STAGING_ROOT/webauthn"
STAGING_LEGACY="$STAGING_ROOT/webauthn-auth"
STAGING_SHARED="$STAGING_ROOT/_shared/webauthn-router"
mkdir -p "$STAGING_CANONICAL" "$STAGING_SHARED"
if [[ $HAS_LEGACY -eq 1 ]]; then
  mkdir -p "$STAGING_LEGACY"
fi
cleanup() {
  rm -rf "$STAGING_ROOT"
}
trap cleanup EXIT

log "Staging canonical WebAuthn payload in ${STAGING_CANONICAL}"
rsync -a --delete \
  --include='package.json' \
  --include='package-lock.json' \
  --include='README.md' \
  --include='CHANGELOG.md' \
  --include='dist/***' \
  --exclude='*' \
  "$EXT_CANONICAL_DIR"/ "$STAGING_CANONICAL"/
rsync -a "$SHARED_ROUTER_DIR"/ "$STAGING_SHARED"/

if [[ $HAS_LEGACY -eq 1 ]]; then
  log "Staging legacy WebAuthn payload in ${STAGING_LEGACY}"
  rsync -a --delete \
    --include='package.json' \
    --include='package-lock.json' \
    --include='README.md' \
    --include='CHANGELOG.md' \
    --include='dist/***' \
    --exclude='*' \
    "$EXT_LEGACY_DIR"/ "$STAGING_LEGACY"/
  rsync -a "$SHARED_ROUTER_DIR"/ "$STAGING_SHARED"/
fi

log "Installing production dependencies for canonical WebAuthn in ${STAGING_CANONICAL} (npm ci --omit=dev)"
(cd "$STAGING_CANONICAL" && npm ci --omit=dev)

if [[ $HAS_LEGACY -eq 1 ]]; then
  log "Installing production dependencies for legacy WebAuthn in ${STAGING_LEGACY} (npm ci --omit=dev)"
  (cd "$STAGING_LEGACY" && npm ci --omit=dev)
fi

shopt -s nullglob
mapfile -t TARGETS < <(compgen -G "$BASE_PATTERN")
shopt -u nullglob

if (( ${#TARGETS[@]} == 0 )); then
  echo "No targets matched pattern: $BASE_PATTERN" >&2
  exit 1
fi

log "Found ${#TARGETS[@]} target directories matching $BASE_PATTERN"
for target in "${TARGETS[@]}"; do
  resolved=$(realpath "$target")
  base_dir="${resolved%/}"
  base_name=$(basename "$base_dir")

  deploy_root="$base_dir"
  if [[ "$base_name" == "webauthn" || "$base_name" == "webauthn-auth" ]]; then
    deploy_root=$(dirname "$base_dir")
  fi

  dest_path_canonical="${deploy_root}/webauthn"
  dest_path_legacy="${deploy_root}/webauthn-auth"

  log "Deploying shared WebAuthn router to ${deploy_root}/_shared/webauthn-router"
  mkdir -p "$deploy_root/_shared/webauthn-router"
  rsync -a --delete "$STAGING_SHARED"/ "$deploy_root/_shared/webauthn-router"/

  log "Deploying canonical WebAuthn extension to ${dest_path_canonical}"
  mkdir -p "$dest_path_canonical"
  rsync -a --delete "$STAGING_CANONICAL"/ "$dest_path_canonical"/

  if [[ $HAS_LEGACY -eq 1 ]]; then
    log "Deploying legacy WebAuthn extension to ${dest_path_legacy}"
    mkdir -p "$dest_path_legacy"
    rsync -a --delete "$STAGING_LEGACY"/ "$dest_path_legacy"/
  else
    log "Legacy WebAuthn payload skipped; configure reverse proxy /webauthn-auth -> /webauthn if required"
  fi

  log "Ensure WebAuthn env vars (WEBAUTHN_RP_ID, WEBAUTHN_RP_NAME, WEBAUTHN_ORIGINS, WEBAUTHN_TIMEOUT_MS) are set for ${deploy_root}."
  log "Deployment to ${deploy_root}/{webauthn,webauthn-auth} completed"
done

log "All deployments finished. Restart the Directus services for changes to take effect."

if [[ -n "$ENV_PATH" && ! -f "$ENV_PATH" ]]; then
  log "ERROR: env file not found at $ENV_PATH"
  exit 1
fi

log "Ensuring webauthn_credentials schema (mode=$MODE, env-path=${ENV_PATH:-<env>}, pk-policy=$PK_POLICY) via provision helper"
PROVISION_ARGS=(--mode "$MODE" --pk-policy "$PK_POLICY")
if [[ -n "$ENV_PATH" ]]; then
  PROVISION_ARGS+=(--env-path "$ENV_PATH")
fi
if [[ "$MODE" == "prod" ]]; then
  if [[ -n "$DEV_ENV_PATH" ]]; then
    PROVISION_ARGS+=(--sync-from-dev --dev-env-path "$DEV_ENV_PATH" --allow-destructive)
  else
    log "WARNING: --dev-env-path not supplied; skipping --sync-from-dev for prod provisioning."
  fi
fi
python3 "$PROVISION_SCRIPT" "${PROVISION_ARGS[@]}"

log "Optional UUID migration: run tools/migrations/webauthn_pk_migrate.py manually with DB credentials if you want UUID PKs"

log "Enforcing WebAuthn permissions for users to manage their own credentials (mode=$MODE)"
python3 "$REPO_ROOT/tools/enforce_webauthn_permissions.py" --mode "$MODE"

BASE_URL=$(resolve_base_url "$ENV_PATH" "$MODE" || true)
TOKEN=$(resolve_token "$ENV_PATH" "$MODE" || true)

if [[ -z "$BASE_URL" ]]; then
  log "WARNING: Directus base URL missing; skipping endpoint smoke checks"
  exit 0
fi

if [[ -n "$TOKEN" ]]; then
  HEALTH_STATUS=$(curl -sk -o /tmp/webauthn_health.json -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE_URL/webauthn/health" || true)
  if [[ "$HEALTH_STATUS" != "200" ]]; then
    log "WARNING: /webauthn/health returned $HEALTH_STATUS for $BASE_URL"
  else
    log "Health check OK for $BASE_URL/webauthn/health"
  fi

  CRED_STATUS=$(curl -sk -o /tmp/webauthn_credentials.json -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE_URL/webauthn/credentials" || true)
  if [[ "$CRED_STATUS" != "200" ]]; then
    log "WARNING: /webauthn/credentials returned $CRED_STATUS for $BASE_URL"
  else
    log "Credential listing reachable for $BASE_URL/webauthn/credentials"
  fi
else
  log "WARNING: Directus token not found; skipping endpoint smoke checks"
fi
