#!/usr/bin/env bash
# file: releases/package-webauthn/provisioning/provision_webauthn_collections.sh
# purpose: Provision WebAuthn collections in Directus via API
# version: 1.0.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex
# last_reviewed_at: 2026-03-01T04:30:00Z

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: provision_webauthn_collections.sh --mode <dev|prod> [--env-path <path>] [--pk-policy <policy>]
                                         [--sync-from-dev --dev-env-path <path> --allow-destructive]

Calls the WebAuthn provisioning helper using explicit mode and optional env files.
USAGE
}

MODE=""
ENV_PATH=""
DEV_ENV_PATH=""
PK_POLICY="accept-existing"
SYNC_FROM_DEV=0
ALLOW_DESTRUCTIVE=0

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
    --dev-env-path)
      DEV_ENV_PATH=${2:-}
      shift 2
      ;;
    --pk-policy)
      PK_POLICY=${2:-}
      shift 2
      ;;
    --sync-from-dev)
      SYNC_FROM_DEV=1
      shift 1
      ;;
    --allow-destructive)
      ALLOW_DESTRUCTIVE=1
      shift 1
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

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RELEASE_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
PROVISION_SCRIPT="${RELEASE_ROOT}/webauthn/tools/provision_webauthn_collection.py"

if [[ ! -f "$PROVISION_SCRIPT" ]]; then
  echo "Provisioning helper not found at $PROVISION_SCRIPT" >&2
  exit 1
fi

ARGS=(--mode "$MODE" --pk-policy "$PK_POLICY")
if [[ -n "$ENV_PATH" ]]; then
  ARGS+=(--env-path "$ENV_PATH")
fi
if [[ $SYNC_FROM_DEV -eq 1 ]]; then
  if [[ -z "$DEV_ENV_PATH" ]]; then
    echo "--dev-env-path is required when --sync-from-dev is set" >&2
    exit 1
  fi
  ARGS+=(--sync-from-dev --dev-env-path "$DEV_ENV_PATH")
fi
if [[ $ALLOW_DESTRUCTIVE -eq 1 ]]; then
  ARGS+=(--allow-destructive)
fi

python3 "$PROVISION_SCRIPT" "${ARGS[@]}"
