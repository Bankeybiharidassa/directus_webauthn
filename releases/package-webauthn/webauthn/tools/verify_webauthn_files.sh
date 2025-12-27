#!/usr/bin/env bash
# file: tools/verify_webauthn_files.sh
# purpose: Validate the presence of WebAuthn extension entrypoints and build artifacts
# version: 1.0.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex
# last_reviewed_at: 2026-01-17T00:00:00Z

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CANONICAL_DIR="$REPO_ROOT/extensions/endpoints/webauthn"
LEGACY_DIR="$REPO_ROOT/extensions/endpoints/webauthn-auth"
SHARED_DIR="$REPO_ROOT/extensions/endpoints/_shared/webauthn-router"
REQUIRE_DIST=0
ALLOW_MISSING_LEGACY=0

usage() {
  cat <<'USAGE'
Usage: verify_webauthn_files.sh [--require-dist] [--allow-missing-legacy]

Checks that the canonical, legacy, and shared WebAuthn extension entrypoints exist.
Use --require-dist to also enforce the presence of built dist/index.js artifacts.
Use --allow-missing-legacy when the legacy alias is intentionally omitted.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-dist)
      REQUIRE_DIST=1
      shift 1
      ;;
    --allow-missing-legacy)
      ALLOW_MISSING_LEGACY=1
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

missing=()

check_entrypoint() {
  local dir="$1" label="$2"
  if [[ ! -d "$dir" ]]; then
    missing+=("${label} directory missing: $dir")
    return
  fi

  if [[ ! -f "$dir/src/index.ts" && ! -f "$dir/src/index.js" ]]; then
    missing+=("${label} entrypoint missing: $dir/src/index.{ts,js}")
  fi

  if [[ $REQUIRE_DIST -eq 1 && ! -f "$dir/dist/index.js" ]]; then
    missing+=("${label} build artifact missing: $dir/dist/index.js")
  fi
}

check_entrypoint "$CANONICAL_DIR" "Canonical"

if [[ $ALLOW_MISSING_LEGACY -eq 1 ]]; then
  if [[ ! -d "$LEGACY_DIR" ]]; then
    echo "Legacy directory intentionally absent; skipping legacy checks" >&2
  else
    echo "Legacy checks skipped by flag; not enforcing presence" >&2
  fi
else
  check_entrypoint "$LEGACY_DIR" "Legacy"
fi

if [[ ! -f "$SHARED_DIR/index.ts" ]]; then
  missing+=("Shared router entrypoint missing: $SHARED_DIR/index.ts")
fi

if (( ${#missing[@]} > 0 )); then
  printf 'WebAuthn file verification failed:\n'
  for item in "${missing[@]}"; do
    printf ' - %s\n' "$item"
  done
  printf 'Re-run the WebAuthn build (npm ci && npm run build) or restore missing files.\n'
  exit 1
fi

printf 'WebAuthn file verification passed.%s\n' "$( (( REQUIRE_DIST )) && echo ' (dist enforced)' )"
