// file: tools/webauthn/replay/replay_http.ts
// purpose: Replay captured WebAuthn login start/finish payloads against DEV Directus to confirm error handling
// version: 1.0.0
// git_commit: <pending>
// git_repo: https://github.com/openaiproxy/kibana2directus
// mode: DEV
// last_reviewed_by: codex

import path from 'node:path';
import { envConfig, postJson, readJson, writeJson } from './shared.js';

interface ExtractedStart {
  request: { body: any };
  response: { body: any };
}
interface ExtractedFinish {
  request: { body: any };
  response: { body: any };
}

async function main() {
  const { baseUrl } = envConfig();
  const useExtractedStart = process.argv.includes('--use-extracted-start');
  const extractedStart = loadOptional<ExtractedStart>('fixtures/extracted_start.json');
  const extractedFinish = loadOptional<ExtractedFinish>('fixtures/extracted_finish.json');

  if (!extractedFinish?.request?.body) {
    throw new Error('fixtures/extracted_finish.json missing request.body');
  }

  const email = extractedStart?.request?.body?.email || extractedFinish.request.body?.email;
  if (!email) {
    throw new Error('Unable to infer email from fixtures');
  }

  const liveStartBody = { email };
  const startResponse = await postJson(`${baseUrl}/webauthn-auth/login/start`, liveStartBody);

  const finishPayload = extractedFinish.request.body;
  const finishResponse = await postJson(`${baseUrl}/webauthn-auth/login/finish`, finishPayload);

  const report = {
    baseUrl,
    email,
    useExtractedStart,
    startStatus: startResponse.status,
    finishStatus: finishResponse.status,
    startBody: useExtractedStart ? extractedStart?.response?.body ?? null : startResponse.body,
    extractedStartBody: extractedStart?.response?.body ?? null,
    finishBody: finishResponse.body,
  };

  writeJson(path.join('reports', 'http_replay.json'), report);
  console.log('HTTP replay complete', report);
}

function loadOptional<T>(relativePath: string): T | null {
  try {
    return readJson<T>(relativePath);
  } catch {
    return null;
  }
}

main().catch((error) => {
  console.error('replay_http failed', error);
  process.exit(1);
});
