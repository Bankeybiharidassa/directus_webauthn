#!/usr/bin/env bash
# file: install_webauthn_extension.sh
# purpose: convenience wrapper to invoke tools/install_webauthn_extension.sh from the repo root
# version: 1.0.1
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex
# last_reviewed_at: 2026-01-16T12:20:00Z

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TARGET_SCRIPT="$SCRIPT_DIR/tools/install_webauthn_extension.sh"

if [[ ! -x "$TARGET_SCRIPT" ]]; then
  echo "WebAuthn installer not found or not executable at $TARGET_SCRIPT" >&2
  echo "Pull the repository or check the tools/ directory before retrying. The repository should contain tools/install_webauthn_extension.sh." >&2
  exit 1
fi

exec "$TARGET_SCRIPT" "$@"
