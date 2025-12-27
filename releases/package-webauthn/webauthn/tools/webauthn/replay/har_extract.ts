// file: tools/webauthn/replay/har_extract.ts
// purpose: Extract WebAuthn login start/finish payloads from a HAR file for replay and local verification
// version: 1.0.0
// git_commit: <pending>
// git_repo: https://github.com/openaiproxy/kibana2directus
// mode: DEV
// last_reviewed_by: codex

import fs from 'node:fs';
import path from 'node:path';
import { BASE_DIR, writeJson } from './shared.js';

const HAR_PATH = path.resolve(BASE_DIR, 'fixtures/directus.har');

function loadHar() {
  if (!fs.existsSync(HAR_PATH)) {
    throw new Error(`HAR file not found at ${HAR_PATH}`);
  }
  const raw = fs.readFileSync(HAR_PATH, 'utf8');
  return JSON.parse(raw);
}

function parseBody(entry: any) {
  const text = entry?.text ?? entry?.content?.text ?? null;
  if (!text) return null;
  if (entry?.content?.encoding === 'base64') {
    try {
      const decoded = Buffer.from(text, 'base64').toString('utf8');
      return tryParseJson(decoded);
    } catch (error) {
      return `base64 decode failed: ${(error as Error).message}`;
    }
  }
  return tryParseJson(text);
}

function tryParseJson(value: string) {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function latestEntry(entries: any[], endsWith: string) {
  const matches = entries.filter((entry) => entry.request?.url?.includes(endsWith) && entry.request?.method === 'POST');
  if (matches.length === 0) return null;
  return matches[matches.length - 1];
}

function sanitizeHeaders(headers: any[]) {
  const forbidden = new Set(['cookie', 'authorization', 'set-cookie']);
  return (headers ?? [])
    .filter((h: any) => h?.name && !forbidden.has(h.name.toLowerCase()))
    .map((h: any) => ({ name: h.name, value: h.value }));
}

function extract() {
  const har = loadHar();
  const entries = har?.log?.entries ?? [];
  const start = latestEntry(entries, '/webauthn-auth/login/start');
  const finish = latestEntry(entries, '/webauthn-auth/login/finish');

  const startOut = start
    ? {
        url: start.request?.url,
        request: {
          method: start.request?.method,
          headers: sanitizeHeaders(start.request?.headers),
          body: parseBody(start.request?.postData ?? {}),
        },
        response: {
          status: start.response?.status,
          headers: sanitizeHeaders(start.response?.headers),
          body: parseBody(start.response?.content ?? {}),
        },
      }
    : null;

  const finishOut = finish
    ? {
        url: finish.request?.url,
        request: {
          method: finish.request?.method,
          headers: sanitizeHeaders(finish.request?.headers),
          body: parseBody(finish.request?.postData ?? {}),
        },
        response: {
          status: finish.response?.status,
          headers: sanitizeHeaders(finish.response?.headers),
          body: parseBody(finish.response?.content ?? {}),
        },
      }
    : null;

  if (startOut) {
    writeJson('fixtures/extracted_start.json', startOut);
  }
  if (finishOut) {
    writeJson('fixtures/extracted_finish.json', finishOut);
    const credentialId =
      (finishOut.request.body as any)?.credential?.id || (finishOut.request.body as any)?.credential?.rawId || null;
    if (credentialId) {
      writeJson('fixtures/extracted_finish_credential_id.json', { credentialId });
    }
  }

  writeJson('reports/har_extract_summary.json', {
    foundStart: Boolean(startOut),
    foundFinish: Boolean(finishOut),
    startUrl: startOut?.url ?? null,
    finishUrl: finishOut?.url ?? null,
  });

  console.log('HAR extraction complete');
  console.log(`start found=${Boolean(startOut)} finish found=${Boolean(finishOut)}`);
}

extract();
