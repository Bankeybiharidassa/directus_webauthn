#!/usr/bin/env node
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

function expectOkOrConfigured(result, label) {
  if (result.status === 503 && result.data?.error === 'webauthn_not_configured') {
    if (!Array.isArray(result.data?.details?.missing) || result.data.details.missing.length === 0) {
      throw new Error(`${label}: webauthn_not_configured missing details list`);
    }
    return `${label}: not configured`;
  }
  if (result.status !== 200 || result.data?.ok !== true) {
    throw new Error(`${label}: unexpected response ${result.status}`);
  }
  return `${label}: ok`;
}

function assertOptionsPayload(body, label) {
  if (!body?.publicKey?.challenge || !body?.publicKey?.rpId) {
    throw new Error(`${label}: missing challenge or rpId in publicKey`);
  }
}

(async () => {
  try {
    const creds = await hit('/webauthn/credentials');
    console.log(expectOkOrConfigured(creds, 'credentials'));

    const authOptions = await hit('/webauthn/authentication/options', 'POST', {});
    console.log(expectOkOrConfigured(authOptions, 'authentication/options'));
    if (authOptions.status === 200) assertOptionsPayload(authOptions.data, 'authentication/options');

    const otpOptions = await hit('/webauthn/otp/options', 'POST', {});
    console.log(expectOkOrConfigured(otpOptions, 'otp/options'));
    if (otpOptions.status === 200) assertOptionsPayload(otpOptions.data, 'otp/options');

    console.log('Smoke check completed.');
  } catch (error) {
    console.error('Smoke check failed:', error?.message || error);
    process.exit(1);
  }
})();
