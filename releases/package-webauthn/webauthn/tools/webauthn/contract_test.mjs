#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import { readFileSync, existsSync } from 'node:fs';

function loadEnv() {
  const envPath = process.env.WEBAUTHN_ENV_PATH;
  if (!envPath) return;
  if (!existsSync(envPath)) return;
  const text = readFileSync(envPath, 'utf8');
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const cleaned = line.startsWith('export ') ? line.slice(7).trim() : line;
    const idx = cleaned.indexOf('=');
    if (idx === -1) continue;
    const key = cleaned.slice(0, idx).trim();
    const value = cleaned.slice(idx + 1).trim().replace(/^['"]/, '').replace(/['"]$/, '');
    if (key && !(key in process.env)) process.env[key] = value;
  }
}

loadEnv();

const baseUrl =
  process.env.DIRECTUS_URL_DEV ||
  process.env.DIRECTUS_API_DEV ||
  process.env.DIRECTUS_BASE_URL_DEV ||
  process.env.DIRECTUS_URL ||
  process.env.DIRECTUS_API ||
  process.env.DIRECTUS_BASE_URL;
const token = process.env.DIRECTUS_TOKEN_DEV || process.env.DIRECTUS_API_TOKEN || process.env.DIRECTUS_TOKEN || '';
const headers = { 'content-type': 'application/json' };
if (token) headers['Authorization'] = `Bearer ${token}`;

if (!baseUrl) {
  console.error('Directus base URL is required (set DIRECTUS_URL[_DEV] or WEBAUTHN_ENV_PATH)');
  process.exit(1);
}

async function hit(endpoint, method = 'GET', body) {
  const res = await fetch(`${baseUrl.replace(/\/$/, '')}${endpoint}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

function allowConfigured(result) {
  if (result.status === 503 && result.data?.error === 'webauthn_not_configured') {
    assert.ok(Array.isArray(result.data?.details?.missing) && result.data.details.missing.length > 0);
    return false;
  }
  assert.equal(result.status, 200, `unexpected status ${result.status}`);
  assert.equal(result.data?.ok, true, 'ok flag missing');
  return true;
}

function assertCredentialsPayload(body) {
  assert.ok(Array.isArray(body.credentials), 'credentials must be an array');
  for (const cred of body.credentials) {
    assert.ok(typeof cred.id === 'string' && cred.id, 'credential id required');
    assert.ok(typeof cred.label === 'string' && cred.label, 'credential label required');
    assert.ok(['platform', 'cross-platform', 'unknown'].includes(cred.type), 'credential type invalid');
  }
}

function assertOptionsPayload(body) {
  assert.ok(body?.publicKey?.challenge, 'challenge missing');
  assert.ok(body?.publicKey?.rpId, 'rpId missing');
  assert.ok(Array.isArray(body?.publicKey?.allowCredentials), 'allowCredentials missing');
}

(async () => {
  try {
    const creds = await hit('/webauthn/credentials');
    if (allowConfigured(creds)) assertCredentialsPayload(creds.data);

    const authOptions = await hit('/webauthn/authentication/options', 'POST', {});
    if (allowConfigured(authOptions)) assertOptionsPayload(authOptions.data);

    const otpOptions = await hit('/webauthn/otp/options', 'POST', {});
    if (allowConfigured(otpOptions)) {
      assertOptionsPayload(otpOptions.data);
      assert.equal(otpOptions.data?.context?.flow, 'drytest');
    }

    console.log('Contract validation passed.');
  } catch (error) {
    console.error('Contract validation failed:', error?.message || error);
    process.exit(1);
  }
})();
