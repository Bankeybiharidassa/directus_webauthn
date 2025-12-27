#!/usr/bin/env python3
# file: tools/verify_webauthn_storage_contract.py
# purpose: Verify WebAuthn storage contracts via Directus API (no direct DB access)
# version: 3.1.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex
# last_reviewed_at: 2026-03-01T04:00:00Z

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

REPORT_DIR = os.path.join('reports')

EXPECTED_FIELDS: Mapping[str, Sequence[str]] = {
    'webauthn_credentials': [
        'id',
        'credential_id',
        'public_key',
        'cose_alg',
        'user',
        'sign_count',
        'transports',
        'aaguid',
        'device_type',
        'backed_up',
        'nickname',
        'user_agent',
        'origin',
        'created_at',
        'updated_at',
        'last_used_at',
    ],
    'webauthn_challenges': [
        'id',
        'challenge_id',
        'user',
        'challenge',
        'type',
        'expires_at',
        'created_at',
        'used_at',
        'rp_id',
        'origin',
    ],
}


@dataclass
class ApiContext:
    base_url: str
    token: str


def load_env(env_path: Optional[str]) -> Dict[str, str]:
    env: Dict[str, str] = dict(os.environ)
    if not env_path:
        return env
    with open(env_path, 'r', encoding='utf-8') as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            env.setdefault(key.strip(), value.strip().strip('"\''))
    return env


def resolve_env_value(env: Mapping[str, str], keys: Iterable[str]) -> Optional[str]:
    for key in keys:
        value = env.get(key)
        if value:
            return value
    return None


def pick_api_context(mode: str, env_path: Optional[str], overrides: argparse.Namespace) -> ApiContext:
    env = load_env(env_path)
    base_url = overrides.base_url or resolve_env_value(
        env,
        [
            'DIRECTUS_URL_DEV' if mode == 'dev' else 'DIRECTUS_URL',
            'DIRECTUS_API_DEV' if mode == 'dev' else 'DIRECTUS_API',
            'DIRECTUS_BASE_URL_DEV' if mode == 'dev' else 'DIRECTUS_BASE_URL',
            'APP_BASE_URL_DEV' if mode == 'dev' else 'APP_BASE_URL',
            'PUBLIC_URL_DEV' if mode == 'dev' else 'PUBLIC_URL',
        ],
    )
    token = overrides.token or resolve_env_value(
        env,
        [
            'DIRECTUS_TOKEN_DEV' if mode == 'dev' else 'DIRECTUS_TOKEN',
            'DIRECTUS_DEMO_TOKEN_DEV' if mode == 'dev' else 'DIRECTUS_API_TOKEN',
        ],
    )
    if not base_url or not token:
        raise RuntimeError('Directus base URL or token missing')
    return ApiContext(base_url=base_url.rstrip('/'), token=token)


def api_request(ctx: ApiContext, method: str, path: str) -> Tuple[int, dict]:
    url = f"{ctx.base_url}/{path.lstrip('/')}"
    headers = {
        'Authorization': f'Bearer {ctx.token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    req = urllib.request.Request(url, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode('utf-8') or '{}'
            return resp.getcode(), json.loads(body)
    except urllib.error.HTTPError as err:
        body = err.read().decode('utf-8') if err.fp else '{}'
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {'error': body or err.reason}
        return err.code, parsed
    except urllib.error.URLError as err:
        return 0, {'error': getattr(err, 'reason', str(err))}


def verify_api(ctx: ApiContext) -> Dict[str, object]:
    result: Dict[str, object] = {
        'base_url': ctx.base_url,
        'via': 'api',
        'missing_collections': [],
        'missing_fields': {},
        'collections': {},
    }

    for collection, fields in EXPECTED_FIELDS.items():
        status, coll_body = api_request(ctx, 'GET', f'collections/{collection}')
        if status != 200:
            result['missing_collections'].append(collection)
            continue

        status, fields_body = api_request(ctx, 'GET', f'fields/{collection}?limit=-1')
        if status != 200:
            result['missing_fields'][collection] = list(fields)
            continue

        entries = fields_body.get('data') if isinstance(fields_body, dict) else None
        names = set()
        if isinstance(entries, list):
            for entry in entries:
                name = entry.get('field') or entry.get('name')
                if name:
                    names.add(name)
        missing = [field for field in fields if field not in names]
        if missing:
            result['missing_fields'][collection] = missing
        result['collections'][collection] = {'fields_present': sorted(names)}

    result['ok'] = not result['missing_collections'] and not result['missing_fields']
    return result


def persist_reports(payload: Mapping[str, object]) -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)
    json_path = os.path.join(REPORT_DIR, 'webauthn_storage_verify.json')
    md_path = os.path.join(REPORT_DIR, 'webauthn_storage_verify.md')
    with open(json_path, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, indent=2)

    lines = [
        '# WebAuthn storage verification',
        f"- ok: {payload.get('ok')}",
        f"- modes: {', '.join(payload.get('modes', [])) if isinstance(payload.get('modes'), list) else ''}\n",
    ]
    for key in ('missing_collections', 'missing_fields'):
        if payload.get(key):
            lines.append(f"## {key.replace('_', ' ').title()}")
            if isinstance(payload[key], dict):
                for coll, fields in payload[key].items():
                    lines.append(f"- {coll}: {', '.join(fields)}")
            else:
                for entry in payload[key]:
                    lines.append(f"- {entry}")
    with open(md_path, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(lines))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description='Verify WebAuthn storage against requirements')
    parser.add_argument('--mode', choices=['dev', 'prod'], default='dev', help='Target environment mode')
    parser.add_argument('--env-path', help='Optional env file path to load before resolving variables')
    parser.add_argument('--base-url', help='Override Directus base URL for API verification')
    parser.add_argument('--token', help='Override Directus API token for verification')
    args = parser.parse_args(argv)

    ctx = pick_api_context(args.mode, args.env_path, args)
    api_result = verify_api(ctx)

    combined: MutableMapping[str, object] = dict(api_result)
    combined['modes'] = [args.mode]

    persist_reports(combined)

    if not combined.get('ok'):
        print(json.dumps(combined, indent=2))
        return 1

    print(json.dumps({'status': 'ok', 'checked_collections': list(EXPECTED_FIELDS.keys())}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
