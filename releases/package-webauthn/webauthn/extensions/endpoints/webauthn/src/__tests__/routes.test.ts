import { describe, expect, it } from 'vitest';
import { registerWebauthnRoutes } from 'webauthn-router-shared';

const testHost = process.env.WEBAUTHN_TEST_HOST ?? 'directus.example.com';
const testOrigin = process.env.WEBAUTHN_TEST_ORIGIN ?? `https://${testHost}`;

function createMockContext() {
  const mockSchema = () => {
    const collections = {
      directus_users: {},
      webauthn_credentials: {},
      webauthn_challenges: {},
    } as Record<string, any>;
    const fields: Record<string, any> = {};
    const credentialFields = [
      'id',
      'credential_id',
      'public_key',
      'cose_alg',
      'user',
      'sign_count',
      'transports',
      'aaguid',
      'device_type',
      'backed_up',
      'nickname',
      'user_agent',
      'origin',
      'created_at',
      'updated_at',
      'last_used_at',
    ];
    const challengeFields = [
      'id',
      'user',
      'challenge',
      'type',
      'expires_at',
      'created_at',
      'used_at',
      'rp_id',
      'origin',
    ];
    for (const field of credentialFields) {
      fields[`webauthn_credentials.${field}`] = {};
    }
    for (const field of challengeFields) {
      fields[`webauthn_challenges.${field}`] = {};
    }
    return { collections, fields };
  };

  class StubItemsService {
    collection: string;
    created: any[] = [];
    constructor(collection: string) {
      this.collection = collection;
    }
    async readByQuery() {
      if (this.collection === 'directus_users') {
        return { data: [{ id: 'user-1', email: 'user@example.com' }] };
      }
      return { data: [] };
    }
    async createOne(record: any) {
      this.created.push(record);
      return record;
    }
    async deleteMany() {
      return [];
    }
    async readOne() {
      return null as any;
    }
    async updateOne() {
      return null as any;
    }
  }

  class StubUsersService {
    async readOne() {
      return { id: 'user-1', email: 'user@example.com' };
    }
  }

  return {
    services: { ItemsService: StubItemsService, UsersService: StubUsersService },
    database: {},
    env: {},
    getSchema: async () => mockSchema(),
  } as any;
}

function createMissingStorageContext() {
  const base = createMockContext();
  return {
    ...base,
    getSchema: async () => ({ collections: {}, fields: {} }),
  } as any;
}

function createRouter() {
  const routes: Record<string, (req: any, res: any, next: any) => any> = {};
  const router = {
    get: (path: string, handler: any) => {
      routes[`GET ${path}`] = handler;
    },
    post: (path: string, handler: any) => {
      routes[`POST ${path}`] = handler;
    },
    delete: (path: string, handler: any) => {
      routes[`DELETE ${path}`] = handler;
    },
  } as any;
  return { router, routes };
}

function createRes() {
  return {
    statusCode: 200,
    body: null as any,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: any) {
      this.body = payload;
      return this;
    },
  };
}

describe('webauthn route handlers', () => {
  const baseEnv = {
    WEBAUTHN_RP_ID: testHost,
    WEBAUTHN_RP_NAME: "IT's Secured",
    WEBAUTHN_ORIGINS: testOrigin,
  };

  it('returns authentication options with requestId and publicKey', async () => {
    const { router, routes } = createRouter();
    registerWebauthnRoutes(router, { context: createMockContext(), baseEnv });
    const handler = routes['POST /authentication/options'];
    const res = createRes();
    const req = { body: {}, get: () => testHost, accountability: { user: 'user-1' } } as any;

    await handler(req, res, () => {});

    expect(res.statusCode).toBe(200);
    expect(res.body?.ok).toBe(true);
    expect(res.body?.data?.publicKey?.challenge).toBeTypeOf('string');
    expect(res.body?.data?.publicKey?.rpId).toBe(testHost);
    expect(res.body?.data?.attemptId).toBeTypeOf('string');
    expect(res.body?.meta?.requestId).toBeTypeOf('string');
  });

  it('allows username-based authentication options when logged out', async () => {
    const { router, routes } = createRouter();
    registerWebauthnRoutes(router, { context: createMockContext(), baseEnv });
    const handler = routes['POST /authentication/options'];
    const res = createRes();
    const req = { body: { username: 'user@example.com' }, get: () => testHost, accountability: null } as any;

    await handler(req, res, () => {});

    expect(res.statusCode).toBe(200);
    expect(res.body?.ok).toBe(true);
    expect(res.body?.data?.publicKey?.challenge).toBeTypeOf('string');
    expect(res.body?.data?.attemptId).toBeTypeOf('string');
  });

  it('accepts email alias for authentication options when logged out', async () => {
    const { router, routes } = createRouter();
    registerWebauthnRoutes(router, { context: createMockContext(), baseEnv });
    const handler = routes['POST /authentication/options'];
    const res = createRes();
    const req = { body: { email: 'user@example.com' }, get: () => testHost, accountability: null } as any;

    await handler(req, res, () => {});

    expect(res.statusCode).toBe(200);
    expect(res.body?.ok).toBe(true);
    expect(res.body?.data?.publicKey?.challenge).toBeTypeOf('string');
    expect(res.body?.data?.publicKey?.rpId).toBe(testHost);
  });

  it('allows discoverable authentication options without username', async () => {
    const { router, routes } = createRouter();
    registerWebauthnRoutes(router, { context: createMockContext(), baseEnv });
    const handler = routes['POST /authentication/options'];
    const res = createRes();
    const req = { body: {}, get: () => testHost, accountability: null } as any;

    await handler(req, res, () => {});

    expect(res.statusCode).toBe(200);
    expect(res.body?.ok).toBe(true);
    expect(res.body?.data?.publicKey?.allowCredentials?.length).toBe(0);
    expect(res.body?.data?.context?.user_id).toBeNull();
  });

  it('rejects authentication verify without credential with a 422', async () => {
    const { router, routes } = createRouter();
    registerWebauthnRoutes(router, { context: createMockContext(), baseEnv });
    const handler = routes['POST /authentication/verify'];
    const res = createRes();
    const req = { body: {}, get: () => testHost, accountability: { user: 'user-1' } } as any;

    await handler(req, res, () => {});

    expect(res.statusCode).toBe(400);
    expect(res.body?.error).toBe('invalid_webauthn_response');
  });

  it('redacts storage diagnostics for unauthenticated authentication options', async () => {
    const { router, routes } = createRouter();
    registerWebauthnRoutes(router, { context: createMissingStorageContext(), baseEnv });
    const handler = routes['POST /authentication/options'];
    const res = createRes();
    const req = { body: { username: 'user@example.com' }, get: () => testHost, accountability: null } as any;

    await handler(req, res, () => {});

    expect(res.statusCode).toBe(503);
    expect(res.body?.error).toBe('webauthn_storage_missing');
    expect(res.body?.details).toBeUndefined();
  });

  it('redacts storage diagnostics for admins without diagnostics opt-in', async () => {
    const { router, routes } = createRouter();
    registerWebauthnRoutes(router, { context: createMissingStorageContext(), baseEnv });
    const handler = routes['POST /authentication/options'];
    const res = createRes();
    const req = {
      body: { username: 'user@example.com' },
      get: () => testHost,
      accountability: { admin: true },
    } as any;

    await handler(req, res, () => {});

    expect(res.statusCode).toBe(503);
    expect(res.body?.error).toBe('webauthn_storage_missing');
    expect(res.body?.details).toBeUndefined();
  });

  it('exposes storage diagnostics to admins when diagnostics are public', async () => {
    const { router, routes } = createRouter();
    registerWebauthnRoutes(router, {
      context: createMissingStorageContext(),
      baseEnv: { ...baseEnv, WEBAUTHN_DIAGNOSTICS_PUBLIC: 'true' },
    });
    const handler = routes['POST /authentication/options'];
    const res = createRes();
    const req = {
      body: { username: 'user@example.com' },
      get: () => testHost,
      accountability: { admin: true },
    } as any;

    await handler(req, res, () => {});

    expect(res.statusCode).toBe(503);
    expect(res.body?.error).toBe('webauthn_storage_missing');
    expect(res.body?.details?.missing?.length).toBeGreaterThan(0);
    expect(res.body?.details?.provisionCommand).toContain('provision_webauthn_storage_directus.py');
  });

  it('redacts diagnostics for unauthenticated health calls by default', async () => {
    const { router, routes } = createRouter();
    registerWebauthnRoutes(router, { context: createMockContext(), baseEnv });
    const handler = routes['GET /'];
    const res = createRes();
    const req = { get: () => testHost, accountability: null } as any;

    await handler(req, res, () => {});

    expect(res.statusCode).toBe(200);
    expect(res.body?.ok).toBe(true);
    expect(res.body?.data?.config?.available).toBe(true);
    expect(res.body?.data?.config?.rpId).toBeUndefined();
    expect(res.body?.data?.storage?.missing).toBeUndefined();
    expect(res.body?.data?.storage?.provisionCommand).toBeUndefined();
  });

  it('redacts diagnostics for admins when diagnostics opt-in is disabled', async () => {
    const { router, routes } = createRouter();
    registerWebauthnRoutes(router, { context: createMockContext(), baseEnv });
    const handler = routes['GET /'];
    const res = createRes();
    const req = { get: () => testHost, accountability: { admin: true } } as any;

    await handler(req, res, () => {});

    expect(res.statusCode).toBe(200);
    expect(res.body?.ok).toBe(true);
    expect(res.body?.data?.config?.rpId).toBeUndefined();
    expect(res.body?.data?.storage?.missing).toBeUndefined();
    expect(res.body?.data?.storage?.provisionCommand).toBeUndefined();
  });

  it('returns diagnostic details when explicitly allowed', async () => {
    const { router, routes } = createRouter();
    registerWebauthnRoutes(router, {
      context: createMockContext(),
      baseEnv: { ...baseEnv, WEBAUTHN_DIAGNOSTICS_PUBLIC: 'true' },
    });
    const handler = routes['GET /'];
    const res = createRes();
    const req = { get: () => testHost, accountability: null } as any;

    await handler(req, res, () => {});

    expect(res.statusCode).toBe(200);
    expect(res.body?.ok).toBe(true);
    expect(res.body?.data?.config?.rpId).toBe(testHost);
    expect(res.body?.data?.storage?.missing).toEqual([]);
    expect(res.body?.data?.storage?.provisionCommand).toContain('provision_webauthn_storage_directus.py');
  });
});
