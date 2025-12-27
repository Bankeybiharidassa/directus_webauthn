// file: tools/webauthn/replay/inspect_credentials.ts
// purpose: Inspect stored WebAuthn credentials in DEV Directus and summarize encoding shapes
// version: 1.0.0
// git_commit: <pending>
// git_repo: https://github.com/openaiproxy/kibana2directus
// mode: DEV
// last_reviewed_by: codex

import path from 'node:path';
import {
  canonicalizeBase64Url,
  decodeAnyToBuffer,
  detectBase64Flavor,
  envConfig,
  getJson,
  readJson,
  writeJson,
} from './shared.js';

async function main() {
  const { baseUrl, adminToken } = envConfig();
  if (!adminToken) {
    throw new Error('DIRECTUS_DEV_ADMIN_TOKEN or DIRECTUS_TOKEN_DEV is required');
  }
  const url = `${baseUrl}/items/webauthn_credentials?limit=100&fields=id,user,credential_id,public_key,sign_count,created_at,last_used_at`;
  const json = await getJson(url, adminToken);
  const rows = (json as any)?.data ?? [];

  const extractedFinish = loadFinishCredentialId();
  const finishCredentialId = extractedFinish?.canonical ?? null;

  const summary = rows.map((row: any) => {
    const credIdRaw = row.credential_id;
    const publicKeyRaw = row.public_key;

    let credentialIdType = typeof credIdRaw;
    let credentialIdLen: number | null = null;
    let publicKeyType = typeof publicKeyRaw;
    let publicKeyLen: number | null = null;
    let canonicalId: string | null = null;
    let hasPlusSlash = false;
    let hasPadding = false;

    try {
      const buffer = decodeAnyToBuffer(credIdRaw, 'credential_id');
      credentialIdType = Array.isArray((credIdRaw as any)?.data)
        ? 'object[data]' : Buffer.isBuffer(credIdRaw) ? 'buffer' : typeof credIdRaw;
      credentialIdLen = buffer.length;
      canonicalId = canonicalizeBase64Url(bufferToBase64Url(buffer), 'credential_id');
      const flavor = detectBase64Flavor(typeof credIdRaw === 'string' ? credIdRaw : canonicalId ?? '');
      hasPlusSlash = flavor.hasPlusSlash;
      hasPadding = flavor.hasPadding;
    } catch (error) {
      canonicalId = `invalid: ${(error as Error).message}`;
    }

    try {
      const pkBuffer = decodeAnyToBuffer(publicKeyRaw, 'public_key');
      publicKeyLen = pkBuffer.length;
      publicKeyType = Array.isArray((publicKeyRaw as any)?.data)
        ? 'object[data]' : Buffer.isBuffer(publicKeyRaw) ? 'buffer' : typeof publicKeyRaw;
    } catch (error) {
      publicKeyType = `invalid: ${(error as Error).message}`;
    }

    const record = {
      id: row.id,
      user: row.user,
      credential_id_type: credentialIdType,
      credential_id_len: credentialIdLen,
      canonical_id: canonicalId,
      public_key_type: publicKeyType,
      public_key_len: publicKeyLen,
      sign_count: row.sign_count ?? null,
      has_plus_slash: hasPlusSlash,
      has_padding: hasPadding,
      created_at: row.created_at ?? null,
      last_used_at: row.last_used_at ?? null,
    } as any;

    if (finishCredentialId && canonicalId && canonicalId === finishCredentialId) {
      record.matches_fixture = true;
    }

    return record;
  });

  writeJson(path.join('reports', 'credentials_shape.json'), summary);
  console.table(summary, [
    'id',
    'credential_id_type',
    'credential_id_len',
    'public_key_type',
    'public_key_len',
    'sign_count',
    'has_plus_slash',
    'has_padding',
    'matches_fixture',
  ]);

  if (finishCredentialId) {
    const match = summary.find((row) => row.matches_fixture);
    console.log('fixture credentialId canonical', finishCredentialId, 'matchedRecord', match?.id ?? null);
  }
}

function bufferToBase64Url(buffer: Buffer) {
  return Buffer.isBuffer(buffer) ? buffer.toString('base64url') : '';
}

function loadFinishCredentialId() {
  try {
    const finish = readJson<any>('fixtures/extracted_finish.json');
    const rawId = finish?.request?.body?.credential?.id || finish?.request?.body?.credential?.rawId;
    if (!rawId) return null;
    return { raw: rawId, canonical: canonicalizeBase64Url(rawId, 'fixture credential id') };
  } catch {
    return null;
  }
}

main().catch((error) => {
  console.error('inspect_credentials failed', error);
  process.exit(1);
});
