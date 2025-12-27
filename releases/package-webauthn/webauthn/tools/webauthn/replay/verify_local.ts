// file: tools/webauthn/replay/verify_local.ts
// purpose: Replay captured WebAuthn login finish payload locally using SimpleWebAuthn against stored DEV credentials
// version: 1.0.0
// git_commit: <pending>
// git_repo: https://github.com/openaiproxy/kibana2directus
// mode: DEV
// last_reviewed_by: codex

import path from 'node:path';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import {
  canonicalizeBase64Url,
  decodeAnyToBuffer,
  envConfig,
  getJson,
  readJson,
  writeJson,
} from './shared.js';

interface ExtractedStart {
  response?: { body?: any };
}
interface ExtractedFinish {
  request: { body: any };
}

async function main() {
  const { baseUrl, adminToken } = envConfig();
  if (!baseUrl) throw new Error('DIRECTUS_DEV_URL or DIRECTUS_URL_DEV is required');
  if (!adminToken) throw new Error('DIRECTUS_DEV_ADMIN_TOKEN or DIRECTUS_TOKEN_DEV is required');

  const start = readJson<ExtractedStart>('fixtures/extracted_start.json');
  const finish = readJson<ExtractedFinish>('fixtures/extracted_finish.json');

  const finishBody = finish?.request?.body;
  if (!finishBody?.credential) throw new Error('Finish fixture missing credential');

  const credentials = await loadCredentials(baseUrl, adminToken);
  const normalizedFinishId = canonicalizeBase64Url(
    finishBody.credential.id || finishBody.credential.rawId,
    'finish credential id',
  );
  const matchingCredential = credentials.find((c) => c.canonicalId === normalizedFinishId);
  if (!matchingCredential) {
    throw new Error(`No stored credential matches fixture id ${normalizedFinishId}`);
  }

  const authenticator = {
    credentialID: matchingCredential.credentialID,
    credentialPublicKey: matchingCredential.credentialPublicKey,
    counter: matchingCredential.counter,
    transports: finishBody?.credential?.response?.transports,
  } as const;

  const expectedChallenge = start?.response?.body?.options?.challenge;
  const expectedRPID =
    start?.response?.body?.options?.rpId ??
    process.env.WEBAUTHN_RP_ID ??
    new URL(baseUrl).hostname;
  const expectedOrigin =
    process.env.WEBAUTHN_ORIGIN ??
    process.env.WEBAUTHN_ORIGINS?.split(',')[0] ??
    new URL(baseUrl).origin;

  if (!expectedChallenge) {
    throw new Error('Missing challenge from extracted start fixture');
  }

  const verification = await verifyAuthenticationResponse({
    response: finishBody.credential,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    authenticator,
    requireUserVerification: true,
  });

  const report = {
    verified: verification.verified,
    newCounter: verification.authenticationInfo?.newCounter ?? null,
    credentialMatch: matchingCredential.id,
    expectedRPID,
    expectedChallenge,
  };

  writeJson(path.join('reports', 'verify_local.json'), report);
  console.log('Local verification result', report);
}

async function loadCredentials(baseUrl: string, token: string) {
  const url = `${baseUrl}/items/webauthn_credentials?limit=100&fields=id,user,credential_id,public_key,sign_count`;
  const json = await getJson(url, token);
  const rows = (json as any)?.data ?? [];
  return rows
    .map((row: any) => {
      try {
        const credentialID = decodeAnyToBuffer(row.credential_id, `credential_id row ${row.id}`);
        const credentialPublicKey = decodeAnyToBuffer(row.public_key, `public_key row ${row.id}`);
        const counter = Number.isFinite(Number(row.sign_count)) ? Number(row.sign_count) : 0;
        return {
          id: row.id,
          canonicalId: isoBase64URL.fromBuffer(credentialID),
          credentialID,
          credentialPublicKey,
          counter,
        };
      } catch (error) {
        return { error: (error as Error).message, id: row.id } as any;
      }
    })
    .filter((row: any) => !row.error);
}

main().catch((error) => {
  console.error('verify_local failed', error);
  process.exit(1);
});
