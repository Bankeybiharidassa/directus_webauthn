#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const envPath = process.env.WEBAUTHN_ENV_PATH;
if (envPath && fs.existsSync(envPath)) {
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line.trim());
    if (m) process.env[m[1]] ??= m[2];
  }
}

const baseUrl = (
  process.env.DIRECTUS_URL_DEV
  || process.env.DIRECTUS_API_DEV
  || process.env.DIRECTUS_BASE_URL_DEV
  || process.env.APP_BASE_URL_DEV
  || process.env.PUBLIC_URL_DEV
  || process.env.DIRECTUS_URL
  || process.env.DIRECTUS_API
  || process.env.DIRECTUS_BASE_URL
  || process.env.APP_BASE_URL
  || process.env.PUBLIC_URL
);
const token = process.env.DIRECTUS_TOKEN_DEV || process.env.DIRECTUS_DEMO_TOKEN_DEV || process.env.DIRECTUS_TOKEN;
const apply = process.env.APPLY === 'true';

if (!baseUrl) {
  console.error('Directus base URL is required (set DIRECTUS_URL[_DEV] or equivalent)');
  process.exit(1);
}

if (!token) {
  console.error('Directus token is required (set DIRECTUS_TOKEN_DEV or DIRECTUS_TOKEN)');
  process.exit(1);
}

function normalizeB64Url(value) {
  if (typeof value !== 'string') throw new Error('credential_id must be a string');
  const trimmed = value.trim();
  if (!trimmed) throw new Error('empty credential_id');
  const swapped = trimmed.replace(/\+/g, '-').replace(/\//g, '_');
  return swapped.replace(/=+$/g, '');
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Request failed ${res.status}: ${text}`);
  }
  return res.json();
}

async function main() {
  const list = await fetchJson(
    `${baseUrl}/items/webauthn_credentials?limit=-1&fields=id,credential_id,sign_count`,
  );
  const rows = list?.data ?? list ?? [];
  const report = [];
  for (const row of rows) {
    const current = row.credential_id;
    try {
      const normalized = normalizeB64Url(String(current));
      if (normalized !== current) {
        report.push({ id: row.id, old: current, new: normalized });
        if (apply) {
          await fetchJson(`${baseUrl}/items/webauthn_credentials/${row.id}`, {
            method: 'PATCH',
            body: JSON.stringify({ credential_id: normalized, sign_count: row.sign_count ?? 0 }),
          });
        }
      }
    } catch (error) {
      report.push({ id: row.id, error: (error).message });
    }
  }
  console.log(JSON.stringify({ updated: apply, changes: report }, null, 2));
}

main().catch((error) => {
  console.error('Normalization failed', error);
  process.exit(1);
});
