#!/usr/bin/env python3
# file: tools/provision_webauthn_collection.py
# purpose: Verify and ensure WebAuthn collections/fields exist without altering primary key types
# version: 3.4.0
# git_commit: <pending>
# git_repo: https://github.com/itssecured/kibana2directus
# mode: SHARED
# last_reviewed_by: codex
# last_reviewed_at: 2026-02-26T00:00:00Z

import argparse
import copy
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

CollectionSpec = Dict[str, object]
FieldSpec = Dict[str, object]
RelationSpec = Dict[str, object]

PK_POLICIES = (
    'accept-existing',
    'enforce-directus-contract',
)


def load_env(env_path: Optional[str]) -> Dict[str, str]:
    env: Dict[str, str] = dict(os.environ)
    if not env_path:
        return env
    if not os.path.isfile(env_path):
        raise FileNotFoundError(f"env file not found: {env_path}")

    with open(env_path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            env.setdefault(key.strip(), value.strip().strip('"\''))
    return env


def pick_first(env: Dict[str, str], keys: List[str]) -> Tuple[Optional[str], Optional[str]]:
    for key in keys:
        value = env.get(key)
        if value:
            return key, value
    return None, None


def api_request(method: str, base_url: str, token: str, path: str, payload: Optional[dict] = None) -> Tuple[int, dict]:
    url = base_url.rstrip('/') + '/' + path.lstrip('/')
    data = None
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    if payload is not None:
        data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())

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


def call_with_retries(
    func, *, label: str, attempts: int = 3, base_delay: float = 1.0, backoff: float = 2.0
) -> Tuple[int, dict]:
    last_status = None
    last_body: dict = {}
    for attempt in range(1, attempts + 1):
        status, body = func()
        if status not in (0,) and status < 500:
            return status, body

        last_status, last_body = status, body
        if attempt == attempts:
            break

        sleep_for = base_delay * (backoff ** (attempt - 1))
        print(
            f"[WARN] {label} received transient status {status}; "
            f"retrying in {sleep_for:.1f}s ({attempt}/{attempts})"
        )
        time.sleep(sleep_for)

    return last_status or 0, last_body


def extract_expectations(spec: FieldSpec) -> Dict[str, object]:
    expectations: Dict[str, object] = {}
    if 'type' in spec:
        expectations['type'] = spec['type']

    schema = spec.get('schema') or {}
    meta = spec.get('meta') or {}

    for key in (
        'data_type',
        'is_nullable',
        'is_unique',
        'max_length',
        'default_value',
        'foreign_key_table',
        'foreign_key_column',
    ):
        if key in schema:
            expectations[f'schema.{key}'] = schema[key]

    if 'special' in meta:
        expectations['meta.special'] = meta['special']

    return expectations


def read_nested(source: dict, path: str) -> object:
    parts = path.split('.')
    current: object = source
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def detect_mismatches(spec: FieldSpec, existing: dict) -> List[str]:
    mismatches: List[str] = []
    expectations = extract_expectations(spec)
    for path, expected in expectations.items():
        current = read_nested(existing, path)
        if current != expected:
            mismatches.append(f"{path} expected {expected!r} got {current!r}")
    return mismatches


def build_patch(spec: FieldSpec, existing: dict) -> Optional[dict]:
    expectations = extract_expectations(spec)
    patch: Dict[str, object] = {}

    for path, expected in expectations.items():
        current = read_nested(existing, path)
        if current == expected:
            continue

        if path.startswith('schema.'):
            patch.setdefault('schema', {})[path.split('.', 1)[1]] = expected
        elif path.startswith('meta.'):
            patch.setdefault('meta', {})[path.split('.', 1)[1]] = expected
        elif path == 'type':
            patch['type'] = expected
        else:
            return None

    if not patch:
        return None

    return patch


def ensure_collection(base_url: str, token: str, spec: CollectionSpec) -> None:
    status, body = call_with_retries(
        lambda: api_request('GET', base_url, token, f"collections/{spec['collection']}"),
        label=f"inspect collection {spec['collection']}",
    )
    if status == 200:
        print(f"[OK] Collection {spec['collection']} already exists")
        return
    if status not in (404, 400, 403):
        raise RuntimeError(f"Failed to inspect collection {spec['collection']}: {body}")

    status, body = call_with_retries(
        lambda: api_request('POST', base_url, token, 'collections', spec),
        label=f"create collection {spec['collection']}",
    )
    if status not in (200, 201):
        raise RuntimeError(f"Failed to create collection {spec['collection']}: {body}")
    print(f"[CREATED] Collection {spec['collection']}")


def field_already_exists_error(body: dict, field: str) -> bool:
    errors = body.get('errors') if isinstance(body, dict) else None
    if not errors:
        return False
    for error in errors:
        message = str(error.get('message', '')).lower()
        reason = str(error.get('extensions', {}).get('reason', '')).lower()
        if 'already exists' in message and field.lower() in message:
            return True
        if 'already exists' in reason and field.lower() in reason:
            return True
    return False


def null_values_blocking_not_null(body: dict) -> bool:
    errors = body.get('errors')
    if not isinstance(errors, list):
        return False
    for error in errors:
        message = str(error.get('message', '')).lower()
        if 'contains null values' in message:
            return True
        if 'not null' in message and 'null' in message:
            return True
    return False


def create_field_with_nullable_fallback(
    base_url: str,
    token: str,
    collection: str,
    spec: FieldSpec,
    label: str,
) -> Tuple[int, dict]:
    status, body = call_with_retries(
        lambda: api_request('POST', base_url, token, f"fields/{collection}", spec),
        label=label,
    )
    if (
        status >= 500
        and spec.get('schema', {}).get('is_nullable') is False
        and null_values_blocking_not_null(body)
    ):
        fallback_spec = copy.deepcopy(spec)
        fallback_spec.setdefault('schema', {})
        fallback_spec['schema']['is_nullable'] = True
        status, body = call_with_retries(
            lambda: api_request('POST', base_url, token, f"fields/{collection}", fallback_spec),
            label=f"{label} (nullable fallback)",
        )
        if status in (200, 201):
            print(
                f"[WARN] Field {collection}.{spec['field']} created as nullable; "
                "existing rows contain NULL values. Backfill and re-run provisioning to enforce NOT NULL."
            )
    return status, body


def reconcile_existing_field(
    base_url: str,
    token: str,
    collection: str,
    spec: FieldSpec,
    pk_policy: str,
    existing: dict,
) -> None:
    mismatches = detect_mismatches(spec, existing)
    if mismatches:
        summary = ", ".join(mismatches)
        if pk_policy == 'enforce-directus-contract':
            patch = build_patch(spec, existing)
            if not patch:
                raise RuntimeError(
                    f"unsupported by directus route: cannot patch {collection}.{spec['field']} ({summary})"
                )
            status, body = call_with_retries(
                lambda: api_request('PATCH', base_url, token, f"fields/{collection}/{spec['field']}", patch),
                label=f"patch field {collection}.{spec['field']}",
            )
            if status not in (200, 201):
                if null_values_blocking_not_null(body):
                    print(
                        f"[WARN] Field {collection}.{spec['field']} contains NULL values; "
                        "backfill before enforcing NOT NULL."
                    )
                    return
                raise RuntimeError(
                    f"Failed to patch field {collection}.{spec['field']} with directus route: {body}"
                )
            print(f"[PATCHED] Field {collection}.{spec['field']} -> {summary}")
        else:
            print(f"[WARN] {collection}.{spec['field']} differs from contract ({summary}); accept-existing")
    else:
        print(f"[OK] Field {collection}.{spec['field']} already exists")


def ensure_field(base_url: str, token: str, collection: str, spec: FieldSpec, pk_policy: str) -> None:
    existing = fetch_field(base_url, token, collection, spec['field'])
    if existing:
        reconcile_existing_field(base_url, token, collection, spec, pk_policy, existing)
        return

    status, body = create_field_with_nullable_fallback(
        base_url,
        token,
        collection,
        spec,
        f"create field {collection}.{spec['field']}",
    )
    if status == 400 and field_already_exists_error(body, spec['field']):
        existing = fetch_field(base_url, token, collection, spec['field'])
        if existing:
            reconcile_existing_field(base_url, token, collection, spec, pk_policy, existing)
            return
    if status not in (200, 201):
        raise RuntimeError(
            f"Failed to create field {collection}.{spec['field']} (status={status}): {body}"
        )
    print(f"[CREATED] Field {collection}.{spec['field']}")


def ensure_relation(base_url: str, token: str, spec: RelationSpec) -> None:
    filter_query = urllib.parse.urlencode({
        'filter[many_collection][_eq]': spec['many_collection'],
        'filter[many_field][_eq]': spec['many_field'],
        'filter[one_collection][_eq]': spec['one_collection'],
    })
    status, body = call_with_retries(
        lambda: api_request('GET', base_url, token, f'relations?{filter_query}'),
        label=(
            f"inspect relation {spec['many_collection']}.{spec['many_field']} -> "
            f"{spec['one_collection']}"
        ),
    )
    if status == 200 and body.get('data'):
        print(f"[OK] Relation {spec['many_collection']}.{spec['many_field']} -> {spec['one_collection']} already exists")
        return
    if status not in (200, 404, 400, 403):
        raise RuntimeError(f"Failed to inspect relation {spec['many_collection']}.{spec['many_field']}: {body}")

    status, body = call_with_retries(
        lambda: api_request('POST', base_url, token, 'relations', spec),
        label=(
            f"create relation {spec['many_collection']}.{spec['many_field']} -> "
            f"{spec['one_collection']}"
        ),
    )
    if status not in (200, 201):
        raise RuntimeError(
            f"Failed to create relation {spec['many_collection']}.{spec['many_field']} -> {spec['one_collection']}: {body}"
        )
    print(f"[CREATED] Relation {spec['many_collection']}.{spec['many_field']} -> {spec['one_collection']}")


def fetch_fields(base_url: str, token: str, collection: str) -> Dict[str, dict]:
    status, body = call_with_retries(
        lambda: api_request('GET', base_url, token, f"fields/{collection}"),
        label=f"fetch fields {collection}",
    )
    if status != 200:
        raise RuntimeError(f"Failed to fetch fields for {collection}: {body}")
    fields: Dict[str, dict] = {}
    for entry in body.get('data', []):
        if isinstance(entry, dict) and entry.get('field'):
            fields[entry['field']] = entry
    return fields


def fetch_relations(base_url: str, token: str, collection: str) -> List[dict]:
    filter_query = urllib.parse.urlencode({
        'filter[many_collection][_eq]': collection,
    })
    status, body = call_with_retries(
        lambda: api_request('GET', base_url, token, f"relations?{filter_query}"),
        label=f"fetch relations {collection}",
    )
    if status != 200:
        raise RuntimeError(f"Failed to fetch relations for {collection}: {body}")
    return [
        entry
        for entry in body.get('data', [])
        if isinstance(entry, dict) and entry.get('many_collection') and entry.get('many_field')
    ]


def build_field_spec_from_remote(remote: dict) -> FieldSpec:
    schema = remote.get('schema') or {}
    meta = remote.get('meta') or {}
    cleaned_schema = {}
    for key in (
        'data_type',
        'is_nullable',
        'max_length',
        'numeric_precision',
        'numeric_scale',
        'default_value',
        'foreign_key_table',
        'foreign_key_column',
    ):
        if key in schema:
            cleaned_schema[key] = schema[key]
    cleaned_meta = {k: v for k, v in meta.items() if k not in ('id', 'collection', 'field')}
    return {
        'field': remote['field'],
        'type': remote.get('type'),
        'schema': cleaned_schema,
        'meta': cleaned_meta,
    }


def build_field_patch_from_remote(remote: dict, existing: dict) -> Optional[dict]:
    patch: Dict[str, object] = {}
    if remote.get('type') and existing.get('type') != remote.get('type'):
        patch['type'] = remote.get('type')

    remote_schema = remote.get('schema') or {}
    existing_schema = existing.get('schema') or {}
    schema_delta = {}
    for key in (
        'data_type',
        'is_nullable',
        'max_length',
        'numeric_precision',
        'numeric_scale',
        'default_value',
        'foreign_key_table',
        'foreign_key_column',
    ):
        if key in remote_schema and existing_schema.get(key) != remote_schema.get(key):
            schema_delta[key] = remote_schema.get(key)
    if schema_delta:
        patch['schema'] = {**existing_schema, **schema_delta}

    remote_meta = {k: v for k, v in (remote.get('meta') or {}).items() if k not in ('id', 'collection', 'field')}
    existing_meta = existing.get('meta') or {}
    meta_delta = {}
    for key, value in remote_meta.items():
        if existing_meta.get(key) != value:
            meta_delta[key] = value
    if meta_delta:
        patch['meta'] = {**existing_meta, **meta_delta}

    return patch or None


def recreate_field(
    base_url: str,
    token: str,
    collection: str,
    remote: dict,
    allow_destructive: bool,
    label: str,
) -> None:
    if not allow_destructive:
        raise RuntimeError(f"{label}: destructive field recreation disabled")
    status, body = call_with_retries(
        lambda: api_request('DELETE', base_url, token, f"fields/{collection}/{remote['field']}"),
        label=f"delete field {collection}.{remote['field']}",
    )
    if status not in (200, 204):
        raise RuntimeError(f"Failed to delete field {collection}.{remote['field']}: {body}")
    spec = build_field_spec_from_remote(remote)
    status, body = create_field_with_nullable_fallback(
        base_url,
        token,
        collection,
        spec,
        f"recreate field {collection}.{remote['field']}",
    )
    if status not in (200, 201):
        raise RuntimeError(f"Failed to recreate field {collection}.{remote['field']}: {body}")
    print(f"[RECREATED] Field {collection}.{remote['field']}")


def sync_fields_from_source(
    base_url: str,
    token: str,
    collection: str,
    source_fields: Dict[str, dict],
    allow_destructive: bool,
) -> None:
    target_fields = fetch_fields(base_url, token, collection)
    for name, remote in source_fields.items():
        existing = target_fields.get(name)
        if not existing:
            spec = build_field_spec_from_remote(remote)
            status, body = create_field_with_nullable_fallback(
                base_url,
                token,
                collection,
                spec,
                f"create field {collection}.{name} from dev",
            )
            if status not in (200, 201):
                raise RuntimeError(f"Failed to create field {collection}.{name} from dev: {body}")
            print(f"[CREATED] Field {collection}.{name} from dev SSOT")
            continue

        patch = build_field_patch_from_remote(remote, existing)
        if not patch:
            print(f"[OK] Field {collection}.{name} matches dev SSOT")
            continue

        status, body = call_with_retries(
            lambda: api_request('PATCH', base_url, token, f"fields/{collection}/{name}", patch),
            label=f"patch field {collection}.{name} from dev",
        )
        if status not in (200, 201):
            recreate_field(base_url, token, collection, remote, allow_destructive, f"patch failed for {collection}.{name}")
            continue
        print(f"[PATCHED] Field {collection}.{name} aligned to dev SSOT")


def build_relation_spec_from_remote(remote: dict) -> RelationSpec:
    spec: RelationSpec = {
        'many_collection': remote.get('many_collection'),
        'many_field': remote.get('many_field'),
        'one_collection': remote.get('one_collection'),
        'one_field': remote.get('one_field'),
    }
    for key in ('junction_field', 'one_allowed', 'many_allowed', 'sort_field'):
        if key in remote:
            spec[key] = remote.get(key)
    return spec


def relation_matches(remote: dict, target: dict) -> bool:
    keys = ('many_collection', 'many_field', 'one_collection', 'one_field', 'junction_field', 'sort_field')
    for key in keys:
        if remote.get(key) != target.get(key):
            return False
    return True


def sync_relations_from_source(
    base_url: str,
    token: str,
    collection: str,
    source_relations: List[dict],
    allow_destructive: bool,
) -> None:
    target_relations = fetch_relations(base_url, token, collection)
    for remote in source_relations:
        key = (remote.get('many_collection'), remote.get('many_field'))
        if not key[0] or not key[1]:
            continue
        candidates = [
            rel for rel in target_relations
            if rel.get('many_collection') == key[0] and rel.get('many_field') == key[1]
        ]
        if candidates and any(relation_matches(remote, candidate) for candidate in candidates):
            print(f"[OK] Relation {key[0]}.{key[1]} matches dev SSOT")
            continue

        if candidates:
            if not allow_destructive:
                raise RuntimeError(f"relation mismatch for {key[0]}.{key[1]} and destructive repair disabled")
            for candidate in candidates:
                rel_id = candidate.get('id')
                if not rel_id:
                    continue
                status, body = call_with_retries(
                    lambda rel_id=rel_id: api_request('DELETE', base_url, token, f"relations/{rel_id}"),
                    label=f"delete relation {key[0]}.{key[1]}",
                )
                if status not in (200, 204):
                    raise RuntimeError(f"Failed to delete relation {key[0]}.{key[1]}: {body}")

        spec = build_relation_spec_from_remote(remote)
        status, body = call_with_retries(
            lambda: api_request('POST', base_url, token, 'relations', spec),
            label=f"create relation {key[0]}.{key[1]} from dev",
        )
        if status not in (200, 201):
            raise RuntimeError(f"Failed to create relation {key[0]}.{key[1]} from dev: {body}")
        print(f"[CREATED] Relation {key[0]}.{key[1]} from dev SSOT")


def fetch_field(base_url: str, token: str, collection: str, field: str) -> Optional[dict]:
    status, body = call_with_retries(
        lambda: api_request('GET', base_url, token, f"fields/{collection}/{field}"),
        label=f"fetch field {collection}.{field}",
    )
    if status != 200:
        return None
    return body.get('data') or body


def build_specs() -> Tuple[CollectionSpec, List[FieldSpec], RelationSpec]:
    collection = {
        'collection': 'webauthn_credentials',
        'meta': {
            'collection': 'webauthn_credentials',
            'icon': 'key',
            'note': 'WebAuthn credentials',
            'hidden': False,
        },
        'schema': {
            'name': 'webauthn_credentials',
            'comment': 'Passkey credentials for WebAuthn endpoint',
        },
    }

    fields: List[FieldSpec] = [
        {
            'field': 'credential_uuid',
            'type': 'string',
            'meta': {
                'note': 'Optional UUID assigned at creation',
                'hidden': True,
            },
            'schema': {
                'name': 'credential_uuid',
                'data_type': 'character varying',
                'is_nullable': True,
            },
        },
        {
            'field': 'user',
            'type': 'uuid',
            'meta': {
                'special': ['m2o'],
                'interface': 'select-dropdown-m2o',
                'note': 'Owner (directus_users)',
            },
            'schema': {
                'name': 'user',
                'data_type': 'uuid',
                'is_nullable': False,
                'foreign_key_table': 'directus_users',
                'foreign_key_column': 'id',
            },
        },
        {
            'field': 'credential_id',
            'type': 'string',
            'meta': {
                'note': 'Base64url credential ID',
            },
            'schema': {
                'name': 'credential_id',
                'data_type': 'character varying',
                'is_nullable': False,
                'is_unique': True,
                'max_length': 255,
            },
        },
        {
            'field': 'public_key',
            'type': 'text',
            'meta': {
                'note': 'Base64-encoded public key',
            },
            'schema': {
                'name': 'public_key',
                'data_type': 'text',
                'is_nullable': False,
            },
        },
        {
            'field': 'cose_alg',
            'type': 'integer',
            'meta': {
                'note': 'COSE algorithm identifier',
            },
            'schema': {
                'name': 'cose_alg',
                'data_type': 'integer',
                'is_nullable': False,
                'default_value': -7,
            },
        },
        {
            'field': 'sign_count',
            'type': 'integer',
            'meta': {
                'note': 'WebAuthn counter',
            },
            'schema': {
                'name': 'sign_count',
                'data_type': 'integer',
                'is_nullable': False,
                'default_value': 0,
            },
        },
        {
            'field': 'transports',
            'type': 'json',
            'meta': {
                'note': 'Authenticator transports (array of strings)',
                'interface': 'tags',
            },
            'schema': {
                'name': 'transports',
                'data_type': 'json',
                'is_nullable': True,
                'default_value': [],
            },
        },
        {
            'field': 'aaguid',
            'type': 'string',
            'meta': {
                'note': 'Authenticator AAGUID when returned by the platform',
            },
            'schema': {
                'name': 'aaguid',
                'data_type': 'character varying',
                'is_nullable': True,
                'max_length': 64,
            },
        },
        {
            'field': 'device_type',
            'type': 'string',
            'meta': {
                'note': 'Authenticator device type (singleDevice or multiDevice)',
            },
            'schema': {
                'name': 'device_type',
                'data_type': 'character varying',
                'is_nullable': True,
                'max_length': 64,
            },
        },
        {
            'field': 'backed_up',
            'type': 'boolean',
            'meta': {
                'note': 'Indicates whether the credential is backed up',
            },
            'schema': {
                'name': 'backed_up',
                'data_type': 'boolean',
                'is_nullable': True,
            },
        },
        {
            'field': 'nickname',
            'type': 'string',
            'meta': {
                'note': 'Optional credential label',
            },
            'schema': {
                'name': 'nickname',
                'data_type': 'character varying',
                'is_nullable': True,
                'max_length': 255,
            },
        },
        {
            'field': 'rp_id',
            'type': 'string',
            'meta': {
                'note': 'Relying party identifier captured at registration time',
            },
            'schema': {
                'name': 'rp_id',
                'data_type': 'character varying',
                'is_nullable': False,
                'max_length': 255,
            },
        },
        {
            'field': 'created_at',
            'type': 'timestamp',
            'meta': {
                'note': 'Registration timestamp',
            },
            'schema': {
                'name': 'created_at',
                'data_type': 'timestamp with time zone',
                'is_nullable': False,
                'default_value': 'now()',
            },
        },
        {
            'field': 'last_used_at',
            'type': 'timestamp',
            'meta': {
                'note': 'Last login timestamp',
            },
            'schema': {
                'name': 'last_used_at',
                'data_type': 'timestamp with time zone',
                'is_nullable': True,
            },
        },
        {
            'field': 'updated_at',
            'type': 'timestamp',
            'meta': {
                'note': 'Last update timestamp',
            },
            'schema': {
                'name': 'updated_at',
                'data_type': 'timestamp with time zone',
                'is_nullable': True,
            },
        },
        {
            'field': 'user_agent',
            'type': 'string',
            'meta': {
                'note': 'Most recent user-agent',
            },
            'schema': {
                'name': 'user_agent',
                'data_type': 'character varying',
                'is_nullable': True,
                'max_length': 1024,
            },
        },
        {
            'field': 'origin',
            'type': 'string',
            'meta': {
                'note': 'Last known origin',
            },
            'schema': {
                'name': 'origin',
                'data_type': 'character varying',
                'is_nullable': True,
                'max_length': 255,
            },
        },
    ]

    relation: RelationSpec = {
        'many_collection': 'webauthn_credentials',
        'many_field': 'user',
        'one_collection': 'directus_users',
        'one_field': None,
    }

    return collection, fields, relation


def build_challenge_specs() -> Tuple[CollectionSpec, List[FieldSpec], RelationSpec]:
    collection = {
        'collection': 'webauthn_challenges',
        'meta': {
            'collection': 'webauthn_challenges',
            'icon': 'alarm',
            'note': 'WebAuthn challenges persisted for verification',
            'hidden': False,
        },
        'schema': {
            'name': 'webauthn_challenges',
            'comment': 'Stored WebAuthn challenges for authentication/registration',
        },
    }

    fields: List[FieldSpec] = [
        {
            'field': 'challenge_id',
            'type': 'string',
            'meta': {
                'interface': 'input',
                'note': 'Opaque challenge identifier (uuid or nanoid)',
            },
            'schema': {
                'name': 'challenge_id',
                'data_type': 'character varying',
                'is_nullable': False,
                'is_unique': True,
                'max_length': 255,
            },
        },
        {
            'field': 'user',
            'type': 'uuid',
            'meta': {
                'special': ['uuid'],
                'interface': 'input',
            },
            'schema': {
                'name': 'user',
                'data_type': 'uuid',
                'is_nullable': True,
            },
        },
        {
            'field': 'challenge',
            'type': 'text',
            'meta': {
                'interface': 'input',
            },
            'schema': {
                'name': 'challenge',
                'data_type': 'text',
                'is_nullable': False,
            },
        },
        {
            'field': 'type',
            'type': 'string',
            'meta': {
                'interface': 'input',
            },
            'schema': {
                'name': 'type',
                'data_type': 'character varying',
                'is_nullable': False,
                'max_length': 32,
            },
        },
        {
            'field': 'expires_at',
            'type': 'timestamp',
            'meta': {
                'interface': 'datetime',
            },
            'schema': {
                'name': 'expires_at',
                'data_type': 'timestamp with time zone',
                'is_nullable': False,
            },
        },
        {
            'field': 'created_at',
            'type': 'timestamp',
            'meta': {
                'interface': 'datetime',
            },
            'schema': {
                'name': 'created_at',
                'data_type': 'timestamp with time zone',
                'is_nullable': False,
            },
        },
        {
            'field': 'used_at',
            'type': 'timestamp',
            'meta': {
                'interface': 'datetime',
            },
            'schema': {
                'name': 'used_at',
                'data_type': 'timestamp with time zone',
                'is_nullable': True,
            },
        },
        {
            'field': 'rp_id',
            'type': 'string',
            'meta': {
                'interface': 'input',
            },
            'schema': {
                'name': 'rp_id',
                'data_type': 'character varying',
                'is_nullable': False,
                'max_length': 255,
            },
        },
        {
            'field': 'origin',
            'type': 'string',
            'meta': {
                'interface': 'input',
            },
            'schema': {
                'name': 'origin',
                'data_type': 'character varying',
                'is_nullable': False,
            },
        },
    ]

    relation: RelationSpec = {
        'many_collection': 'webauthn_challenges',
        'many_field': 'user',
        'one_collection': 'directus_users',
        'one_field': None,
    }

    return collection, fields, relation


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Verify and ensure WebAuthn collections exist without altering PK types',
    )
    parser.add_argument('--mode', '-m', required=True, choices=['dev', 'prod'], help='Target mode: dev or prod')
    parser.add_argument(
        '--env-path',
        help='Optional env file path to load before resolving variables',
    )
    parser.add_argument(
        '--pk-policy',
        choices=PK_POLICIES,
        default='accept-existing',
        help='Schema handling: accept-existing (default) or enforce-directus-contract',
    )
    parser.add_argument(
        '--include-permissions',
        action='store_true',
        help='Create Directus permissions (skipped by default; use when permission provisioning is required)',
    )
    parser.add_argument(
        '--sync-from-dev',
        action='store_true',
        help='Align target schema with DEV WebAuthn fields/relations (DEV is SSOT)',
    )
    parser.add_argument(
        '--dev-env-path',
        help='Env file path for DEV SSOT alignment (required when --sync-from-dev)',
    )
    parser.add_argument(
        '--allow-destructive',
        action='store_true',
        help='Allow delete/recreate when patching fields or relations fails during SSOT alignment',
    )
    args = parser.parse_args()

    env = load_env(args.env_path)

    if args.mode == 'dev':
        token_key, token = pick_first(env, ['DIRECTUS_TOKEN_DEV', 'DIRECTUS_DEMO_TOKEN_DEV'])
        base_key, base_url = pick_first(env, ['DIRECTUS_URL_DEV', 'DIRECTUS_API_DEV', 'DIRECTUS_BASE_URL_DEV', 'APP_BASE_URL_DEV', 'PUBLIC_URL_DEV'])
    else:
        token_key, token = pick_first(env, ['DIRECTUS_TOKEN', 'DIRECTUS_API_TOKEN'])
        base_key, base_url = pick_first(env, ['DIRECTUS_URL', 'DIRECTUS_API', 'DIRECTUS_BASE_URL', 'APP_BASE_URL', 'PUBLIC_URL'])

    if not token or not base_url:
        raise RuntimeError(f"Missing Directus token or base URL for mode={args.mode}")

    pk_policy = args.pk_policy
    print(
        f"[INFO] Using {token_key} for token and {base_key} for base URL (mode={args.mode}, pk-policy={pk_policy})"
    )

    collection, fields, relation = build_specs()
    challenge_collection, challenge_fields, challenge_relation = build_challenge_specs()

    ensure_collection(base_url, token, collection)
    for field in fields:
        ensure_field(base_url, token, collection['collection'], field, pk_policy)
    ensure_relation(base_url, token, relation)

    ensure_collection(base_url, token, challenge_collection)
    for field in challenge_fields:
        ensure_field(base_url, token, challenge_collection['collection'], field, pk_policy)
    ensure_relation(base_url, token, challenge_relation)

    if args.sync_from_dev:
        if args.mode != 'prod':
            raise RuntimeError('--sync-from-dev is only supported in prod mode')
        if not args.dev_env_path:
            raise RuntimeError('--dev-env-path is required when --sync-from-dev is set')
        dev_env = load_env(args.dev_env_path)
        _, dev_token = pick_first(dev_env, ['DIRECTUS_TOKEN_DEV', 'DIRECTUS_DEMO_TOKEN_DEV'])
        _, dev_base_url = pick_first(
            dev_env,
            ['DIRECTUS_URL_DEV', 'DIRECTUS_API_DEV', 'DIRECTUS_BASE_URL_DEV', 'APP_BASE_URL_DEV', 'PUBLIC_URL_DEV'],
        )
        if not dev_token or not dev_base_url:
            raise RuntimeError('Missing Directus DEV token or base URL for SSOT sync')

        dev_fields_credentials = fetch_fields(dev_base_url, dev_token, collection['collection'])
        dev_fields_challenges = fetch_fields(dev_base_url, dev_token, challenge_collection['collection'])
        dev_relations_credentials = fetch_relations(dev_base_url, dev_token, collection['collection'])
        dev_relations_challenges = fetch_relations(dev_base_url, dev_token, challenge_collection['collection'])

        print("[INFO] Aligning WebAuthn fields and relations to dev SSOT")
        sync_fields_from_source(
            base_url,
            token,
            collection['collection'],
            dev_fields_credentials,
            args.allow_destructive,
        )
        sync_fields_from_source(
            base_url,
            token,
            challenge_collection['collection'],
            dev_fields_challenges,
            args.allow_destructive,
        )
        sync_relations_from_source(
            base_url,
            token,
            collection['collection'],
            dev_relations_credentials,
            args.allow_destructive,
        )
        sync_relations_from_source(
            base_url,
            token,
            challenge_collection['collection'],
            dev_relations_challenges,
            args.allow_destructive,
        )

    credentials_id = fetch_field(base_url, token, collection['collection'], 'id')
    challenges_id = fetch_field(base_url, token, challenge_collection['collection'], 'id')
    if credentials_id is None:
        raise RuntimeError('webauthn_credentials.id is missing after provisioning')
    if challenges_id is None:
        raise RuntimeError('webauthn_challenges.id is missing after provisioning')

    if args.include_permissions:
        roles = api_request('GET', base_url, token, 'roles?limit=-1')[1].get('data') or []
        ownership_filter = {'user': {'_eq': '$CURRENT_USER'}}
        for role in roles:
            role_id = role.get('id')
            if not role_id:
                continue
            for action in ('read', 'delete'):
                ensure_permission(
                    base_url,
                    token,
                    role=str(role_id),
                    collection=collection['collection'],
                    action=action,
                    permissions=ownership_filter,
                )
    else:
        print('[INFO] Permission creation skipped (use --include-permissions to enable)')

    print('[DONE] WebAuthn credential and challenge collections verified')
    return 0


# Permission helper defined late to avoid forward reference issues in type hints

def ensure_permission(
    base_url: str,
    token: str,
    *,
    role: str,
    collection: str,
    action: str,
    permissions: dict,
) -> None:
    filter_query = urllib.parse.urlencode(
        {
            'filter[role][_eq]': role,
            'filter[collection][_eq]': collection,
            'filter[action][_eq]': action,
            'limit': 1,
        }
    )
    status, body = call_with_retries(
        lambda: api_request('GET', base_url, token, f'permissions?{filter_query}'),
        label=f"inspect permission {collection}:{action} for role {role}",
    )
    if status == 200 and (body.get('data') or []):
        print(f"[OK] Permission for role={role}, collection={collection}, action={action} already exists")
        return
    if status not in (200, 404, 400, 403):
        raise RuntimeError(f"Failed to inspect permissions for role={role}, collection={collection}, action={action}: {body}")

    payload = {
        'role': role,
        'collection': collection,
        'action': action,
        'fields': '*',
        'permissions': permissions,
        'validation': permissions,
        'presets': {},
        'policy': {},
    }
    status, body = call_with_retries(
        lambda: api_request('POST', base_url, token, 'permissions', payload),
        label=f"create permission {collection}:{action} for role {role}",
    )
    if status not in (200, 201):
        raise RuntimeError(
            f"Failed to create permission for role={role}, collection={collection}, action={action} (status={status}): {body}"
        )
    print(f"[CREATED] Permission for role={role}, collection={collection}, action={action}")


if __name__ == '__main__':
    sys.exit(main())
