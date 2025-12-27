// file: tools/webauthn/replay/confirm_extension_identity.ts
// purpose: Confirm which WebAuthn endpoint extension is responding by capturing build fingerprints from DEV
// version: 1.0.0
// git_commit: <pending>
// git_repo: https://github.com/openaiproxy/kibana2directus
// mode: DEV
// last_reviewed_by: codex

import path from 'node:path';
import { envConfig, postJson, writeJson } from './shared.js';

interface ProbeResult {
  path: string;
  status: number;
  ok: boolean;
  build: any;
  mode?: string | null;
  hasOptions?: boolean;
  headers: Record<string, string>;
  rawBody?: any;
}

async function probe(pathname: string, email: string): Promise<ProbeResult> {
  const { baseUrl } = envConfig();
  const url = `${baseUrl}${pathname}`;
  const response = await postJson(url, { email });

  const body = response.body ?? {};

  return {
    path: pathname,
    status: response.status,
    ok: response.ok,
    build: body?.build ?? null,
    mode: body?.mode ?? null,
    hasOptions: Boolean(body?.options),
    headers: response.headers ?? {},
    rawBody: body,
  };
}

async function main() {
  const email = process.env.WEBAUTHN_PROBE_EMAIL ?? 'webauthn-identity-check@example.com';
  const endpoints = ['/webauthn-auth/login/start', '/webauthn/login/start'];
  const results: ProbeResult[] = [];

  for (const endpoint of endpoints) {
    try {
      const result = await probe(endpoint, email);
      results.push(result);
      console.log(`probe ${endpoint} status=${result.status} build=${JSON.stringify(result.build)}`);
    } catch (error) {
      results.push({
        path: endpoint,
        status: 0,
        ok: false,
        build: null,
        mode: null,
        hasOptions: false,
        headers: {},
        rawBody: { error: (error as Error).message },
      });
      console.error(`probe ${endpoint} failed`, error);
    }
  }

  const reportPath = path.join('reports', 'extension_identity.json');
  writeJson(reportPath, { timestamp: new Date().toISOString(), results });

  const table = results.map((r) => ({ path: r.path, status: r.status, git: r.build?.git ?? null, version: r.build?.version ?? null }));
  console.table(table);
}

main().catch((error) => {
  console.error('confirm_extension_identity failed', error);
  process.exit(1);
});
