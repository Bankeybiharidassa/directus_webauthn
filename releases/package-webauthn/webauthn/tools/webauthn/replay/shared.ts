// file: tools/webauthn/replay/shared.ts
// purpose: Shared helpers for WebAuthn diagnostic + replay tooling (HAR extraction, credential inspection, local verification)
// version: 1.0.0
// git_commit: <pending>
// git_repo: https://github.com/openaiproxy/kibana2directus
// mode: DEV
// last_reviewed_by: codex

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isoBase64URL } from '@simplewebauthn/server/helpers';

export const BASE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL_REGEX = /^[A-Za-z0-9_-]+={0,2}$/;

export function readJson<T = any>(relativePath: string): T {
  const fullPath = path.resolve(BASE_DIR, relativePath);
  const raw = fs.readFileSync(fullPath, 'utf8');
  return JSON.parse(raw) as T;
}

export function writeJson(relativePath: string, value: unknown) {
  const fullPath = path.resolve(BASE_DIR, relativePath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, JSON.stringify(value, null, 2));
}

export function canonicalizeBase64Url(value: string, context: string): string {
  const trimmed = value?.trim?.();
  if (!trimmed) throw new Error(`${context} missing`);
  try {
    return isoBase64URL.fromBuffer(isoBase64URL.toBuffer(trimmed));
  } catch (error) {
    throw new Error(`${context} is not base64url: ${(error as Error).message}`);
  }
}

export function decodeAnyToBuffer(value: unknown, context: string): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value instanceof ArrayBuffer) return Buffer.from(new Uint8Array(value));
  if (value && typeof value === 'object' && Array.isArray((value as any).data)) return Buffer.from((value as any).data);

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) throw new Error(`${context} missing`);

    const looksClassicBase64 = /[+/]/.test(trimmed);
    if (looksClassicBase64 && BASE64_REGEX.test(trimmed)) {
      try {
        return Buffer.from(trimmed, 'base64');
      } catch (error) {
        throw new Error(`${context} invalid base64: ${(error as Error).message}`);
      }
    }

    if (!looksClassicBase64 && !BASE64URL_REGEX.test(trimmed)) {
      throw new Error(`${context} invalid base64url shape`);
    }

    try {
      return Buffer.from(isoBase64URL.toBuffer(trimmed));
    } catch (error) {
      if (BASE64_REGEX.test(trimmed)) {
        return Buffer.from(trimmed, 'base64');
      }
      throw new Error(`${context} invalid base64url: ${(error as Error).message}`);
    }
  }

  throw new Error(`${context} missing or invalid`);
}

export function detectBase64Flavor(value: string) {
  const hasPlusSlash = /[+/]/.test(value);
  const hasPadding = /=+$/.test(value);
  return { hasPlusSlash, hasPadding };
}

export function envConfig() {
  return {
    baseUrl:
      process.env.DIRECTUS_DEV_URL ??
      process.env.DIRECTUS_URL_DEV ??
      process.env.DIRECTUS_URL ??
      process.env.DIRECTUS_API ??
      '',
    adminToken: process.env.DIRECTUS_DEV_ADMIN_TOKEN ?? process.env.DIRECTUS_TOKEN_DEV ?? '',
  };
}

export async function getJson(url: string, token?: string) {
  const response = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`GET ${url} failed: ${response.status} ${response.statusText} ${body}`);
  }
  return response.json();
}

export async function postJson(url: string, body: unknown, token?: string) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });

  const raw = await response.text();
  let parsed: any = null;
  try {
    parsed = raw ? JSON.parse(raw) : null;
  } catch {
    parsed = raw;
  }
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });

  return { status: response.status, ok: response.ok, body: parsed, headers };
}
