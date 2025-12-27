import { isoBase64URL } from '@simplewebauthn/server/helpers';
import express from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { registerWebauthnRoutes } from 'webauthn-router-shared';

let lastAuthOptionsInput: any = null;
let lastAuthVerifyInput: any = null;
let lastRegVerifyInput: any = null;

const testHost = process.env.WEBAUTHN_TEST_HOST ?? 'directus.example.com';
const testOrigin = process.env.WEBAUTHN_TEST_ORIGIN ?? `https://${testHost}`;

const serverOverrides = {
  generateAuthenticationOptions: async (input?: any) => {
    lastAuthOptionsInput = input;
    return {
      challenge: 'ZmFrZS1jaGFsbGVuZ2U',
      rpID: input?.rpID ?? testHost,
      allowCredentials: input?.allowCredentials ?? [
        { id: new Uint8Array([1, 2, 3]), type: 'public-key', transports: ['internal'] },
      ],
      timeout: input?.timeout ?? 60000,
      userVerification: input?.userVerification ?? 'preferred',
    };
  },
  generateRegistrationOptions: async (input?: any) => ({
    challenge: 'ZmFrZS1jaGFsbGVuZ2U',
    rpID: input?.rpID ?? testHost,
    rpName: input?.rpName ?? "IT's Secured",
    user: input?.user ?? { id: new Uint8Array([1, 2, 3]), name: 'user@example.com', displayName: 'User' },
    excludeCredentials: input?.excludeCredentials ?? [],
    timeout: input?.timeout ?? 60000,
  }),
  verifyAuthenticationResponse: async (input?: any) => {
    lastAuthVerifyInput = input;
    return { verified: true, authenticationInfo: { newCounter: 2 } };
  },
  verifyRegistrationResponse: async (input?: any) => {
    lastRegVerifyInput = input;
    return {
      verified: true,
      registrationInfo: {
        credentialPublicKey: new Uint8Array([1, 2, 3]),
        credentialID: new Uint8Array([1, 2, 3]),
        counter: 1,
      },
    };
  },
};

class StubAuthenticationService {
  knex: any;
  refreshCalls: any[] = [];

  constructor(options: any) {
    const knexImpl = (_table?: string) => ({
      insert: async () => {},
      where: () => ({ del: async () => {} }),
    });

    this.knex = typeof options?.knex === 'function' ? options.knex : knexImpl;
  }

  async refresh(seed: string, opts?: any) {
    this.refreshCalls.push({ seed, opts });
    return { accessToken: 'stub-access', refreshToken: 'stub-refresh', expires: 900000 };
  }
}

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

  const credentials = [
    {
      id: 'cred-1',
      credential_id: isoBase64URL.fromBuffer(Buffer.from('credential-id')),
      public_key: isoBase64URL.fromBuffer(Buffer.from('public-key')),
      sign_count: 1,
      user: 'user-1',
      nickname: 'Primary passkey',
    },
  ];
  const challenges: any[] = [];
  let ctxRef: any = null;

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
      if (this.collection === 'webauthn_credentials') {
        return { data: credentials };
      }
      if (this.collection === 'webauthn_challenges') {
        return { data: challenges };
      }
      return { data: [] };
    }

    async createOne(record: any) {
      this.created.push(record);
      if (this.collection === 'webauthn_challenges') {
        challenges.push(record);
        if (ctxRef) ctxRef.__lastChallenge = record;
      }
      return record;
    }

    async deleteMany() {
      return [];
    }

    async readOne(id: string) {
      if (this.collection === 'webauthn_challenges') {
        return challenges.find((entry) => entry.id === id) ?? null;
      }
      return null as any;
    }

    async updateOne(id: string, patch: Record<string, any>) {
      if (this.collection === 'webauthn_challenges') {
        const idx = challenges.findIndex((entry) => entry.id === id);
        if (idx >= 0) challenges[idx] = { ...challenges[idx], ...patch };
      }
      return null as any;
    }
  }

  class StubUsersService {
    async readOne() {
      return { id: 'user-1', email: 'user@example.com' };
    }
  }

  ctxRef = {
    services: { ItemsService: StubItemsService, UsersService: StubUsersService, AuthenticationService: StubAuthenticationService },
    database: {},
    env: {},
    getSchema: async () => mockSchema(),
    __challenges: challenges,
    __challengeSink: challenges,
    __lastChallenge: null,
  } as any;

  return ctxRef;
}

function buildApp(baseEnv: Record<string, string>, overrides = serverOverrides, opts: { accountability?: any } = {}) {
  const app = express();
  const ctx = createMockContext();
  app.use(express.json());
  app.use((req, _res, next) => {
    const hasCustomAccountability = Object.prototype.hasOwnProperty.call(opts, 'accountability');
    (req as any).accountability = hasCustomAccountability ? opts.accountability : { user: 'user-1' };
    next();
  });
  registerWebauthnRoutes(app as any, { context: ctx, baseEnv, logger: console, overrides });
  return { app, ctx };
}

describe('webauthn router integration', () => {
  const baseEnv = {
    WEBAUTHN_RP_ID: testHost,
    WEBAUTHN_RP_NAME: "IT's Secured",
    WEBAUTHN_ORIGINS: testOrigin,
    WEBAUTHN_MODE: 'dev',
  };

  beforeAll(() => {
    process.env.SESSION_COOKIE_NAME = 'directus_session';
    process.env.REFRESH_TOKEN_COOKIE_NAME = 'directus_refresh_token';
    process.env.SESSION_COOKIE_TTL = '600000';
    process.env.REFRESH_TOKEN_TTL = '600000';
  });

  beforeEach(() => {
    lastAuthOptionsInput = null;
    lastAuthVerifyInput = null;
    lastRegVerifyInput = null;
  });

  it('returns credential listings for the current user', async () => {
    const { app } = buildApp(baseEnv);
    const res = await request(app).get('/credentials').set('host', testHost);
    expect(res.status).toBe(200);
    expect(res.body?.ok).toBe(true);
    expect(Array.isArray(res.body?.credentials)).toBe(true);
    expect(res.body?.credentials?.[0]?.id).toBeDefined();
  });

  it('issues drytest authentication options', async () => {
    const { app } = buildApp(baseEnv);
    const res = await request(app).post('/drytest/options').set('host', testHost).send({});
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body?.ok).toBe(true);
    expect(res.body?.publicKey?.rpId).toBe(testHost);
    expect(typeof res.body?.publicKey?.challenge).toBe('string');
    expect(typeof res.body?.context?.request_id).toBe('string');
  });

  it('creates a Directus session during authentication verify', async () => {
    const { app } = buildApp(baseEnv);
    const start = await request(app)
      .post('/authentication/options')
      .set('host', testHost)
      .send({ email: 'user@example.com' });

    const requestId = start.body?.data?.attemptId;
    const allowCredentialId = isoBase64URL.fromBuffer(Buffer.from('credential-id'));

    expect(start.body?.data?.context).toEqual(
      expect.objectContaining({
        flow: 'login',
        user_id: 'user-1',
        request_id: requestId,
      }),
    );

    const res = await request(app)
      .post('/authentication/verify')
      .set('host', testHost)
      .send({
        attemptId: requestId,
        mode: 'json',
        credential: {
          id: allowCredentialId,
          rawId: allowCredentialId,
          type: 'public-key',
          response: {
            authenticatorData: isoBase64URL.fromBuffer(Buffer.from('auth')), 
            clientDataJSON: isoBase64URL.fromBuffer(Buffer.from('client')), 
            signature: isoBase64URL.fromBuffer(Buffer.from('sig')), 
            userHandle: isoBase64URL.fromBuffer(Buffer.from('user-1')),
          },
          clientExtensionResults: {},
        },
      });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body?.ok).toBe(true);
    expect(res.body?.data?.credentialId).toBeDefined();
    expect(res.body?.data?.access_token).toBe('stub-access');
    expect(res.body?.data?.refresh_token).toBe('stub-refresh');
  });

  it('stores rp/origin metadata with challenges and marks them used on verification', async () => {
    const { app, ctx } = buildApp(baseEnv);

    const start = await request(app)
      .post('/authentication/options')
      .set('host', testHost)
      .send({ email: 'user@example.com' });

    const attemptId = start.body?.data?.attemptId;
    const sink = (ctx as any).__challengeSink;

    expect(Array.isArray(sink)).toBe(true);
    expect(sink.length).toBeGreaterThan(0);

    const savedChallenge = sink[sink.length - 1] ?? (ctx as any).__lastChallenge;
    const rpId = savedChallenge?.rp_id ?? savedChallenge?.rpId ?? null;
    const origin = savedChallenge?.origin ?? (Array.isArray(savedChallenge?.origins) ? savedChallenge.origins[0] : null);
    const usedAt = savedChallenge?.used_at ?? savedChallenge?.usedAt ?? null;

    expect(rpId).toBe(testHost);
    expect(origin).toBe(testOrigin);
    expect(usedAt).toBeNull();

    const allowCredentialId = isoBase64URL.fromBuffer(Buffer.from('credential-id'));

    await request(app)
      .post('/authentication/verify')
      .set('host', testHost)
      .send({
        attemptId,
        credential: {
          id: allowCredentialId,
          rawId: allowCredentialId,
          type: 'public-key',
          response: {
            authenticatorData: isoBase64URL.fromBuffer(Buffer.from('auth')),
            clientDataJSON: isoBase64URL.fromBuffer(Buffer.from('client')),
            signature: isoBase64URL.fromBuffer(Buffer.from('sig')),
            userHandle: isoBase64URL.fromBuffer(Buffer.from('user-1')),
          },
          clientExtensionResults: {},
        },
      });

    const updatedChallenge = (ctx as any).__challenges?.[0];
    expect(typeof updatedChallenge?.used_at).toBe('string');
  });

  it('supports discoverable authentication without a username', async () => {
    const { app, ctx } = buildApp(baseEnv, serverOverrides, { accountability: null });
    const start = await request(app)
      .post('/authentication/options')
      .set('host', testHost)
      .send({});

    expect(start.status, JSON.stringify(start.body)).toBe(200);
    expect(start.body?.ok).toBe(true);
    expect(Array.isArray(start.body?.data?.publicKey?.allowCredentials)).toBe(true);
    expect(start.body?.data?.publicKey?.allowCredentials?.length).toBe(0);
    expect(start.body?.data?.context?.user_id).toBeNull();

    const saved = (ctx as any).__lastChallenge;
    expect(saved?.user).toBeNull();

    const attemptId = start.body?.data?.attemptId;
    const allowCredentialId = isoBase64URL.fromBuffer(Buffer.from('credential-id'));

    const finish = await request(app)
      .post('/authentication/verify')
      .set('host', testHost)
      .send({
        attemptId,
        credential: {
          id: allowCredentialId,
          rawId: allowCredentialId,
          type: 'public-key',
          response: {
            authenticatorData: isoBase64URL.fromBuffer(Buffer.from('auth')),
            clientDataJSON: isoBase64URL.fromBuffer(Buffer.from('client')),
            signature: isoBase64URL.fromBuffer(Buffer.from('sig')),
            userHandle: isoBase64URL.fromBuffer(Buffer.from('user-1')),
          },
          clientExtensionResults: {},
        },
      });

    expect(finish.status, JSON.stringify(finish.body)).toBe(200);
    expect(finish.body?.ok).toBe(true);
    expect(finish.body?.data?.credentialId).toBeDefined();
    expect(finish.body?.data?.context?.user_id).toBe('user-1');
  });

  it('ignores client-provided rpId overrides in authentication options', async () => {
    const { app } = buildApp(baseEnv);
    const res = await request(app)
      .post('/authentication/options')
      .set('host', testHost)
      .send({ rpId: 'malicious.example', email: 'user@example.com' });

    expect(res.statusCode).toBe(200);
    expect(res.body?.ok).toBe(true);
    expect(res.body?.data?.publicKey?.rpId).toBe(testHost);
    expect(lastAuthOptionsInput?.rpID).toBe(testHost);
  });

  it('serves login aliases for authentication options/verify with identical contract', async () => {
    const { app } = buildApp(baseEnv);
    const start = await request(app)
      .post('/login/start')
      .set('host', testHost)
      .send({ email: 'user@example.com', identifier: 'user@example.com' });

    expect(start.status, JSON.stringify(start.body)).toBe(200);
    expect(start.body?.ok).toBe(true);
    expect(typeof start.body?.data?.publicKey?.challenge).toBe('string');
    expect(start.body?.data?.publicKey?.rpId).toBe(testHost);
    expect(typeof start.body?.data?.attemptId).toBe('string');
    expect(start.body?.data?.context).toEqual(
      expect.objectContaining({
        flow: 'login',
        user_id: 'user-1',
        request_id: start.body?.data?.attemptId,
      }),
    );

    const attemptId = start.body?.data?.attemptId;
    const allowCredentialId = isoBase64URL.fromBuffer(Buffer.from('credential-id'));

    const finish = await request(app)
      .post('/login/finish')
      .set('host', testHost)
      .send({
        attemptId,
        mode: 'json',
        credential: {
          id: allowCredentialId,
          rawId: allowCredentialId,
          type: 'public-key',
          response: {
            authenticatorData: isoBase64URL.fromBuffer(Buffer.from('auth')),
            clientDataJSON: isoBase64URL.fromBuffer(Buffer.from('client')),
            signature: isoBase64URL.fromBuffer(Buffer.from('sig')),
            userHandle: isoBase64URL.fromBuffer(Buffer.from('user-1')),
          },
          clientExtensionResults: {},
        },
      });

    expect(finish.status, JSON.stringify(finish.body)).toBe(200);
    expect(finish.body?.ok).toBe(true);
    expect(finish.body?.data?.credentialId).toBeDefined();
    expect(finish.body?.data?.access_token).toBe('stub-access');
  });

  it('does not force user verification when policy is preferred', async () => {
    const { app } = buildApp(baseEnv);
    const start = await request(app)
      .post('/authentication/options')
      .set('host', testHost)
      .send({ email: 'user@example.com' });

    const attemptId = start.body?.data?.attemptId;
    const allowCredentialId = isoBase64URL.fromBuffer(Buffer.from('credential-id'));

    await request(app)
      .post('/authentication/verify')
      .set('host', testHost)
      .send({
        attemptId,
        credential: {
          id: allowCredentialId,
          rawId: allowCredentialId,
          type: 'public-key',
          response: {
            authenticatorData: isoBase64URL.fromBuffer(Buffer.from('auth')),
            clientDataJSON: isoBase64URL.fromBuffer(Buffer.from('client')),
            signature: isoBase64URL.fromBuffer(Buffer.from('sig')),
            userHandle: isoBase64URL.fromBuffer(Buffer.from('user-1')),
          },
          clientExtensionResults: {},
        },
      });

    expect(lastAuthVerifyInput?.requireUserVerification).toBe(false);
  });

  it('requires user verification when policy is set to required', async () => {
    const strictEnv = { ...baseEnv, WEBAUTHN_USER_VERIFICATION: 'required' };
    const { app } = buildApp(strictEnv);

    const start = await request(app)
      .post('/authentication/options')
      .set('host', testHost)
      .send({ email: 'user@example.com' });

    const attemptId = start.body?.data?.attemptId;
    const allowCredentialId = isoBase64URL.fromBuffer(Buffer.from('credential-id'));

    await request(app)
      .post('/authentication/verify')
      .set('host', testHost)
      .send({
        attemptId,
        credential: {
          id: allowCredentialId,
          rawId: allowCredentialId,
          type: 'public-key',
          response: {
            authenticatorData: isoBase64URL.fromBuffer(Buffer.from('auth')),
            clientDataJSON: isoBase64URL.fromBuffer(Buffer.from('client')),
            signature: isoBase64URL.fromBuffer(Buffer.from('sig')),
            userHandle: isoBase64URL.fromBuffer(Buffer.from('user-1')),
          },
          clientExtensionResults: {},
        },
      });

    expect(lastAuthVerifyInput?.requireUserVerification).toBe(true);
  });

  it('rejects authentication verify when sign count regresses', async () => {
    const { app } = buildApp(baseEnv, {
      ...serverOverrides,
      verifyAuthenticationResponse: async () => ({ verified: true, authenticationInfo: { newCounter: 0 } }),
    });

    const start = await request(app)
      .post('/authentication/options')
      .set('host', testHost)
      .send({ email: 'user@example.com' });

    const attemptId = start.body?.data?.attemptId;
    const allowCredentialId = isoBase64URL.fromBuffer(Buffer.from('credential-id'));

    const finish = await request(app)
      .post('/authentication/verify')
      .set('host', testHost)
      .send({
        attemptId,
        credential: {
          id: allowCredentialId,
          rawId: allowCredentialId,
          type: 'public-key',
          response: {
            authenticatorData: isoBase64URL.fromBuffer(Buffer.from('auth')),
            clientDataJSON: isoBase64URL.fromBuffer(Buffer.from('client')),
            signature: isoBase64URL.fromBuffer(Buffer.from('sig')),
            userHandle: isoBase64URL.fromBuffer(Buffer.from('user-1')),
          },
          clientExtensionResults: {},
        },
      });

    expect(finish.status, JSON.stringify(finish.body)).toBe(401);
    expect(finish.body?.error).toBe('invalid_webauthn_credentials');
  });

  it('issues registration options and accepts registration verify responses', async () => {
    const { app } = buildApp(baseEnv);
    const start = await request(app)
      .post('/registration/options')
      .set('host', testHost)
      .send({});

    expect(start.status, JSON.stringify(start.body)).toBe(200);
    expect(start.body?.ok).toBe(true);
    expect(typeof start.body?.data?.publicKey?.challenge).toBe('string');
    expect(start.body?.data?.publicKey?.rp?.id ?? start.body?.data?.publicKey?.rpId).toBe(testHost);
    expect(start.body?.data?.publicKey?.user?.id).toBeDefined();
    expect(start.body?.data?.context).toEqual(
      expect.objectContaining({
        flow: 'registration',
        user_id: 'user-1',
        request_id: start.body?.data?.attemptId,
      }),
    );

    const finish = await request(app)
      .post('/registration/verify')
      .set('host', testHost)
      .send({ credential: {} });

    expect(finish.status, JSON.stringify(finish.body)).toBe(200);
    expect(finish.body?.ok).toBe(true);
    expect(finish.body?.data?.credentialId).toBeDefined();
    expect(finish.body?.data?.userId).toBe('user-1');
  });
});
