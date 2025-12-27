# file: tools/enforce_webauthn_permissions.py
# purpose: Enforce ownership-scoped WebAuthn permissions for selected Directus access policies
# version: 1.0.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex
# last_reviewed_at: 2025-12-15T00:00:00Z
"""Apply ownership-based `webauthn_credentials` permissions to selected policies.

This utility aligns create/read/update/delete permissions so users can only
manage their own WebAuthn credentials via Directus access policies. It loads
Directus credentials from the SSOT env file for the requested mode and applies
server-side presets/filters to enforce ownership.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from env_loader import load_env
from replicate_directus_schema import DirectusClient

log = logging.getLogger(__name__)


DEFAULT_POLICY_NAMES = ("Partner", "Enduser")
COLLECTION = "webauthn_credentials"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=["dev", "prod"],
        default="dev",
        help="Target environment (dev or prod). Defaults to dev.",
    )
    parser.add_argument(
        "--policy",
        dest="policies",
        action="append",
        default=[],
        help=(
            "Policy name or slug to enforce. Can be provided multiple times. "
            "Defaults to Partner and Enduser."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print intended changes without writing to Directus.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity.",
    )
    return parser.parse_args(argv)


def _configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")


def _resolve_env_value(env: Mapping[str, str], keys: Iterable[str]) -> Optional[str]:
    for key in keys:
        value = env.get(key)
        if value:
            return value
    return None


def _load_directus_client(mode: str) -> DirectusClient:
    env = load_env(mode=mode, override=False)
    base_url = _resolve_env_value(
        os.environ,
        (
            "DIRECTUS_BASE_URL_DEV" if mode == "dev" else "DIRECTUS_BASE_URL",
            "DIRECTUS_URL_DEV" if mode == "dev" else "DIRECTUS_URL",
            "DIRECTUS_API_DEV" if mode == "dev" else "DIRECTUS_API",
        ),
    )
    token = _resolve_env_value(
        os.environ,
        (
            "DIRECTUS_TOKEN_DEV" if mode == "dev" else "DIRECTUS_TOKEN",
            "DIRECTUS_API_TOKEN" if mode == "prod" else "DIRECTUS_DEMO_TOKEN_DEV",
        ),
    )
    if not base_url or not token:
        raise RuntimeError("Directus base URL or token missing after env load")
    return DirectusClient(base_url=base_url, token=token)


def _normalise_policy_name(value: Optional[str]) -> Optional[str]:
    return value.lower() if value else None


def _index_policies(policies: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for entry in policies:
        for key in ("name", "slug"):
            alias = _normalise_policy_name(entry.get(key))
            if alias:
                index[alias] = entry
    return index


def _desired_payload(action: str, policy_id: str) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "collection": COLLECTION,
        "action": action,
        "policy": policy_id,
        "role": None,
        "fields": ["*"],
    }
    if action == "create":
        base.update(
            {
                "presets": {"user": "$CURRENT_USER.id"},
                "validation": {"user": {"_eq": "$CURRENT_USER.id"}},
            }
        )
    else:
        base.update({"permissions": {"user": {"_eq": "$CURRENT_USER.id"}}})
    return base


def _dicts_equal(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def _find_existing(
    permissions: Sequence[Dict[str, Any]],
    *,
    policy_id: str,
    action: str,
) -> Optional[Dict[str, Any]]:
    for entry in permissions:
        if (
            entry.get("collection") == COLLECTION
            and entry.get("action") == action
            and (entry.get("policy") == policy_id)
        ):
            role_ref = entry.get("role")
            if role_ref is None or role_ref == "":
                return entry
    return None


def apply_permissions(
    client: DirectusClient,
    policy_ids: Sequence[str],
    *,
    dry_run: bool = False,
) -> Dict[str, int]:
    existing_permissions = client.list_permissions(collection=COLLECTION)
    created = 0
    updated = 0

    for policy_id in policy_ids:
        for action in ("create", "read", "update", "delete"):
            desired = _desired_payload(action, policy_id)
            current = _find_existing(existing_permissions, policy_id=policy_id, action=action)
            if current:
                diff: Dict[str, Any] = {}
                for key, value in desired.items():
                    if key in {"collection", "action"}:
                        continue
                    if key not in current or not _dicts_equal(current.get(key), value):
                        diff[key] = value
                if diff:
                    log.info("Updating %s/%s for policy %s", COLLECTION, action, policy_id)
                    if not dry_run:
                        client.update_permission(current["id"], diff)
                    updated += 1
                continue

            payload = dict(desired)
            if not dry_run:
                client.create_permission(payload)
            log.info("Created %s/%s for policy %s", COLLECTION, action, policy_id)
            created += 1
    return {"created": created, "updated": updated}


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = parse_args(argv)
    _configure_logging(args.verbose)

    client = _load_directus_client(mode=args.mode)
    policy_names = args.policies or list(DEFAULT_POLICY_NAMES)

    policies = client.list_policies()
    policy_index = _index_policies(policies)

    resolved_policy_ids: List[str] = []
    for name in policy_names:
        entry = policy_index.get(_normalise_policy_name(name))
        if not entry:
            raise SystemExit(f"Policy '{name}' not found in {args.mode} environment")
        policy_id = entry.get("id")
        if not policy_id:
            raise SystemExit(f"Policy '{name}' is missing an id")
        resolved_policy_ids.append(policy_id)

    summary = apply_permissions(client, resolved_policy_ids, dry_run=args.dry_run)
    log.info("Permission enforcement complete: %s", summary)


if __name__ == "__main__":
    main()
