#!/usr/bin/env bash
# file: releases/package-webauthn/provisioning/install_directus_11.sh
# purpose: Install prerequisites and Directus 11 CLI for a vanilla deployment
# version: 1.0.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex
# last_reviewed_at: 2026-03-01T04:30:00Z

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: install_directus_11.sh --mode <dev|prod> [--project-path <path>] [--init]

Installs OS prerequisites and the Directus 11 CLI. Use --init to optionally
run the Directus initializer in the target project path.
USAGE
}

MODE=""
PROJECT_PATH="directus-11"
RUN_INIT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode)
      MODE=${2:-}
      shift 2
      ;;
    --project-path)
      PROJECT_PATH=${2:-}
      shift 2
      ;;
    --init)
      RUN_INIT=1
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

log() {
  printf '[%s] %s\n' "$(date --utc +"%Y-%m-%dT%H:%M:%SZ")" "$*"
}

install_python_module() {
  local module="$1"
  local apt_pkg="python3-${module}"
  if apt-get install -y "$apt_pkg"; then
    return 0
  fi
  log "APT install failed for ${apt_pkg}; falling back to pip"
  python3 -m pip install --upgrade "$module"
}

log "Installing OS prerequisites (mode=$MODE)"
apt-get update -y
apt-get install -y \
  ca-certificates \
  curl \
  gnupg \
  jq \
  python3 \
  python3-venv \
  python3-pip \
  nodejs \
  npm

install_python_module "requests"
install_python_module "psycopg2"

if ! command -v directus >/dev/null 2>&1; then
  log "Installing Directus CLI (directus@11)"
  npm install -g directus@11
else
  log "Directus CLI already installed"
fi

if [[ $RUN_INIT -eq 1 ]]; then
  log "Initializing Directus project at ${PROJECT_PATH}"
  npx directus@11 init "$PROJECT_PATH"
else
  log "Skipping Directus init. Run: npx directus@11 init ${PROJECT_PATH}"
fi

log "Directus 11 installer complete"
