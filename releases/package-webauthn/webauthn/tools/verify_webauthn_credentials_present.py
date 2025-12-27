#!/usr/bin/env python3
# file: tools/verify_webauthn_credentials_present.py
# purpose: Verify that Directus contains WebAuthn credentials (DEV default)
# version: 1.1.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: DEV
# last_reviewed_by: codex
# last_reviewed_at: 2026-02-26T12:00:00Z
"""Verify that Directus contains WebAuthn credentials and redact secrets."""
from __future__ import annotations

import json
import os
import sys
from typing import Any
from urllib.parse import urljoin

import requests


def main() -> int:
    base_url = os.getenv("DIRECTUS_URL_DEV") or os.getenv("DIRECTUS_API_DEV")
    token = os.getenv("DIRECTUS_TOKEN_DEV")
    if not base_url or not token:
        print("DIRECTUS_URL_DEV and DIRECTUS_TOKEN_DEV are required", file=sys.stderr)
        return 1

    url = urljoin(
        base_url if base_url.endswith('/') else base_url + '/',
        'items/webauthn_credentials?sort=-date_created&limit=5',
    )
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    try:
        response = requests.get(url, headers=headers, timeout=15)
    except Exception as error:  # pragma: no cover - runtime guard
        print(f"request_failed: {error}", file=sys.stderr)
        return 1

    if response.status_code != 200:
        print(f"request_failed: status={response.status_code} body={response.text}", file=sys.stderr)
        return 1

    try:
        payload: Any = response.json()
    except json.JSONDecodeError:
        print("invalid_json_response", file=sys.stderr)
        return 1

    data = payload.get("data") if isinstance(payload, dict) else None
    rows = data if isinstance(data, list) else []
    if not rows:
        print("no_credentials_found", file=sys.stderr)
        return 1

    sanitized: Any = []
    for row in rows:
        if isinstance(row, dict):
            clone = dict(row)
            if "public_key" in clone:
                clone["public_key"] = "<redacted>"
            sanitized.append(clone)
    print(json.dumps({"count": len(rows), "first": sanitized[0] if sanitized else None}))
    return 0


if __name__ == "__main__":
  raise SystemExit(main())
