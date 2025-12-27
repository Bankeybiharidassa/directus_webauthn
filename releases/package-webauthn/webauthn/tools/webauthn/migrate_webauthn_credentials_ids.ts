#!/usr/bin/env ts-node
// file: tools/webauthn/migrate_webauthn_credentials_ids.ts
// purpose: Canonicalize stored WebAuthn credential_ids to base64url and backfill sign_count
// version: 1.0.1
// git_commit: <pending>
// git_repo: https://github.com/openaiproxy/kibana2directus
// mode: DEV
// last_reviewed_by: codex

import fs from 'node:fs';
import path from 'node:path';

const BASE_URL = process.env.DIRECTUS_URL_DEV ?? process.env.DIRECTUS_URL ?? '';
const TOKEN = process.env.DIRECTUS_TOKEN_DEV ?? process.env.DIRECTUS_DEMO_TOKEN_DEV ?? '';
const APPLY = process.argv.includes('--apply');
const OUT_DIR = path.join(__dirname, 'diagnostics');

if (!TOKEN) {
  console.error('DIRECTUS_TOKEN_DEV (or DIRECTUS_DEMO_TOKEN_DEV) is required');
  process.exit(1);
}

if (!BASE_URL) {
  console.error('DIRECTUS_URL_DEV (or DIRECTUS_URL) is required');
  process.exit(1);
}

const BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function toBase64Url(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64Url(value: string): Buffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const paddingNeeded = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + '='.repeat(paddingNeeded);
  return Buffer.from(padded, 'base64');
}

function decodeCredentialIdToBuffer(value: unknown, context: string): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof ArrayBuffer) return Buffer.from(new Uint8Array(value));
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value && typeof value === 'object' && Array.isArray((value as any).data)) return Buffer.from((value as any).data);

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) throw new Error(`${context}: credential_id missing`);

    try {
      return fromBase64Url(trimmed);
    } catch (error) {
      if (BASE64_REGEX.test(trimmed)) {
        return Buffer.from(trimmed, 'base64');
      }
      throw new Error(`${context}: credential_id invalid base64`);
    }
  }

  throw new Error(`${context}: credential_id missing or invalid`);
}

async function request(pathName: string, init: RequestInit = {}) {
  const response = await fetch(`${BASE_URL}${pathName}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${TOKEN}`,
      ...(init.headers ?? {}),
    },
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Request failed ${response.status} ${response.statusText}: ${text}`);
  }

  return response.json();
}

async function loadCredentials() {
  return request('/items/webauthn_credentials?limit=-1');
}

async function updateCredential(id: string | number, data: Record<string, any>) {
  return request(`/items/webauthn_credentials/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  });
}

async function run() {
  const outReport = path.join(
    OUT_DIR,
    APPLY
      ? `migrate_webauthn_credentials_ids_applied_${Date.now()}.json`
      : `migrate_webauthn_credentials_ids_dryrun_${Date.now()}.json`,
  );
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const payload = await loadCredentials();
  const credentials = Array.isArray((payload as any)?.data) ? (payload as any).data : (payload as any) ?? [];
  const changes: any[] = [];

  for (const cred of credentials) {
    try {
      const buffer = decodeCredentialIdToBuffer(cred?.credential_id, 'migration');
      const canonicalId = toBase64Url(buffer);
      const signCountRaw = cred?.sign_count;
      const signCountNumber =
        typeof signCountRaw === 'number' && Number.isFinite(signCountRaw)
          ? signCountRaw
          : typeof signCountRaw === 'string' && signCountRaw.trim() !== ''
            ? Number(signCountRaw)
            : 0;
      const nextSignCount = Number.isFinite(signCountNumber) ? signCountNumber : 0;
      const needsIdUpdate = typeof cred?.credential_id !== 'string' || cred.credential_id !== canonicalId;
      const needsCounterUpdate = signCountRaw === null || Number.isNaN(nextSignCount);

      if (needsIdUpdate || needsCounterUpdate) {
        changes.push({
          id: cred.id,
          previous: { credential_id: cred.credential_id, sign_count: cred.sign_count },
          next: { credential_id: canonicalId, sign_count: nextSignCount },
        });
      }
    } catch (error: any) {
      changes.push({ id: cred?.id ?? null, error: String(error?.message ?? error) });
    }
  }

  const report = { applied: APPLY, base_url: BASE_URL, total: credentials.length, changes };
  fs.writeFileSync(outReport, JSON.stringify(report, null, 2));

  if (APPLY) {
    for (const change of changes) {
      if (change?.next && change?.id) {
        await updateCredential(change.id, change.next);
      }
    }
  }

  console.log(`Wrote ${outReport}`);
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
