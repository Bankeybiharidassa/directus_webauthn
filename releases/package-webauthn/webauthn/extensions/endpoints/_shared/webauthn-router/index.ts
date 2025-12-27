import type { Router, Request, Response, NextFunction, CookieOptions } from 'express';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { randomUUID } from 'node:crypto';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { nanoid } from 'nanoid';
import { ConfigError, resolveConfigForRequest, requestHostname, type WebAuthnConfig } from './env.js';
import { resolveExceptions, type WebauthnExceptions } from './exceptions.js';
import { loadBuildInfo } from './build-info.js';
import {
  ensureWebauthnStorage,
  REQUIRED_CHALLENGE_FIELDS as STORAGE_REQUIRED_CHALLENGE_FIELDS,
  REQUIRED_CREDENTIAL_FIELDS as STORAGE_REQUIRED_CREDENTIAL_FIELDS,
  StorageSchemaError,
  toStorageDiagnostics,
} from './storage.js';
import { STORAGE_CONTRACT, credentialsFieldNames, challengesFieldNames } from './storage-contract.js';
import { assertNoDriftConfig, CHALLENGES_COLLECTION, CREDENTIALS_COLLECTION } from './storage-names.js';
import { normalizeToBuffer as normalizeToBufferLoose, redactCredentialPayload, toBase64Url } from './utils.js';
import type { ApiExtensionContext } from './types.js';
import {
  getWebauthnCredentialsFieldMap,
  WebauthnSchemaMappingError,
  type WebauthnCredentialsFieldMap,
  type WebauthnCredentialsFieldMapResult,
} from './schema-map.js';
import { EXT_VERSION } from './version.js';

type AuthenticatorTransportFuture = 'ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb';

const REQUIRED_CREDENTIAL_FIELDS = ['id', ...credentialsFieldNames, 'created_at', 'updated_at'];
const REQUIRED_CHALLENGE_FIELDS = ['id', ...challengesFieldNames, 'created_at'];

const REGISTERED_ROUTE_PATTERNS = [
  '/',
  '/health',
  '/diag',
  '/diag/build',
  '/diag/schema',
  '/diag/match',
  '/registration/options',
  '/registration/verify',
  '/registration/start',
  '/registration/finish',
  '/authentication/options',
  '/authentication/verify',
  '/login/start',
  '/login/finish',
  '/login/verify',
  '/register/start',
  '/register/finish',
  '/drytest/options',
  '/drytest/verify',
  '/otp/options',
  '/otp/verify',
  '/credentials',
  '/credentials/',
  '/credentials/:id',
];

type ChallengeType = 'registration' | 'authentication';
type ChallengeFlow = 'auth' | 'drytest' | 'registration';

type StoredChallenge = {
  id: number;
  challenge_id?: string | null;
  user: string | null;
  challenge: string;
  type: ChallengeType;
  expires_at: string;
  used_at?: string | null;
  rp_id?: string | null;
  origin?: string | null;
};

type StoredCredential = {
  id: number;
  credential_uuid?: string | null;
  credential_id: string;
  public_key: string;
  user: string;
  sign_count?: number | null;
  cose_alg?: number | null;
  transports?: string[] | null;
  aaguid?: string | null;
  device_type?: string | null;
  backed_up?: boolean | null;
  nickname?: string | null;
  origin?: string | null;
  user_agent?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  last_used_at?: string | null;
};

type NormalizedExceptions = Required<WebauthnExceptions>;
type WebAuthnServerOverrides = Partial<{
  generateAuthenticationOptions: typeof generateAuthenticationOptions;
  generateRegistrationOptions: typeof generateRegistrationOptions;
  verifyAuthenticationResponse: typeof verifyAuthenticationResponse;
  verifyRegistrationResponse: typeof verifyRegistrationResponse;
}>;

class ValidationError extends Error {}
class ForbiddenError extends Error {}
class StorageUnavailableError extends Error {
  missing?: string[];
  provisionCommand?: string;

  constructor(messageOrOptions?: string | { missing?: string[]; provisionCommand?: string }) {
    super(typeof messageOrOptions === 'string' ? messageOrOptions : 'WebAuthn storage unavailable');
    this.name = 'StorageUnavailableError';
    if (messageOrOptions && typeof messageOrOptions !== 'string') {
      this.missing = messageOrOptions.missing;
      this.provisionCommand = messageOrOptions.provisionCommand;
    }
  }
}

class BadRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BadRequestError';
  }
}

class RegistrationInfoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RegistrationInfoError';
  }
}

class PersistError extends Error {
  reason?: string;
  details?: any;

  constructor(message: string, reason?: string, details?: any) {
    super(message);
    this.name = 'PersistError';
    if (reason) this.reason = reason;
    if (details) this.details = details;
  }
}

function getIPFromReq(req: Request): string | null {
  const forwarded = (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim();
  if (forwarded) return forwarded;
  return (req as any).ip ?? (req.socket as any)?.remoteAddress ?? null;
}

function createDefaultAccountability(meta: { ip?: string | null; userAgent?: string | null; origin?: string | null }) {
  const accountability: Record<string, any> = { admin: false, app: null, user: null, role: null };
  if (meta.ip) accountability.ip = meta.ip;
  if (meta.userAgent) accountability.userAgent = meta.userAgent;
  if (meta.origin) accountability.origin = meta.origin;
  return accountability;
}

function parseDurationToMs(value: string | undefined, fallbackMs: number): number {
  if (!value) return fallbackMs;
  const trimmed = value.trim();
  if (!trimmed) return fallbackMs;
  const match = trimmed.match(/^(\d+)(ms|s|m|h|d)?$/i);
  if (!match) return fallbackMs;
  const amount = Number(match[1]);
  const unit = (match[2] ?? 'ms').toLowerCase();
  switch (unit) {
    case 'ms':
      return amount;
    case 's':
      return amount * 1000;
    case 'm':
      return amount * 60 * 1000;
    case 'h':
      return amount * 60 * 60 * 1000;
    case 'd':
      return amount * 24 * 60 * 60 * 1000;
    default:
      return fallbackMs;
  }
}

function parseChallengeTtlToMs(rawValue: string | undefined, fallbackMs: number): number {
  if (!rawValue) return fallbackMs;
  const trimmed = rawValue.trim();
  if (!trimmed) return fallbackMs;
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number(trimmed);
    return Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : fallbackMs;
  }
  return parseDurationToMs(trimmed, fallbackMs);
}

function cookieOptionsFromEnv(env: Record<string, string | undefined>, type: 'refresh' | 'session'): CookieOptions {
  const secureKey = type === 'refresh' ? 'REFRESH_TOKEN_COOKIE_SECURE' : 'SESSION_COOKIE_SECURE';
  const sameSiteKey = type === 'refresh' ? 'REFRESH_TOKEN_COOKIE_SAME_SITE' : 'SESSION_COOKIE_SAME_SITE';
  const domainKey = type === 'refresh' ? 'REFRESH_TOKEN_COOKIE_DOMAIN' : 'SESSION_COOKIE_DOMAIN';
  const pathKey = type === 'refresh' ? 'REFRESH_TOKEN_COOKIE_PATH' : 'SESSION_COOKIE_PATH';

  const secureRaw = env[secureKey];
  const secure = typeof secureRaw === 'string' ? secureRaw.trim().toLowerCase() !== 'false' : true;
  const sameSiteRaw = env[sameSiteKey];
  const sameSite = (sameSiteRaw as CookieOptions['sameSite']) ?? 'lax';
  const domain = env[domainKey];
  const path = env[pathKey] ?? '/';

  const base: CookieOptions = {
    httpOnly: true,
    secure,
    sameSite,
    path,
  };

  if (domain) base.domain = domain;
  return base;
}

function buildProvisionCommand(baseEnv: Record<string, string | undefined>): string {
  const mode = isDevEnv(baseEnv) ? 'dev' : 'prod';
  const candidates = [] as string[];
  if (typeof baseEnv.WEBAUTHN_ENV_FILE === 'string' && baseEnv.WEBAUTHN_ENV_FILE.trim()) {
    candidates.push(baseEnv.WEBAUTHN_ENV_FILE.trim());
  }
  if (typeof baseEnv.WEBAUTHN_ENV_PATHS === 'string' && baseEnv.WEBAUTHN_ENV_PATHS.trim()) {
    const first = baseEnv.WEBAUTHN_ENV_PATHS.split(',').map((entry) => entry.trim()).filter(Boolean)[0];
    if (first) candidates.push(first);
  }

  const envPath = candidates[0];
  const envArgs = envPath ? ` --env ${envPath}` : '';
  return `python3 tools/provision_webauthn_storage_directus.py --mode ${mode}${envArgs}`;
}

function collectionExists(schema: any, collection: string): boolean {
  if (!schema) return false;
  const collections = (schema as any).collections;
  if (!collections) return false;

  if (collections instanceof Map) {
    return collections.has(collection);
  }

  if (typeof collections === 'object') {
    return Boolean((collections as any)[collection]);
  }

  return false;
}

function fieldExists(schema: any, collection: string, field: string): boolean {
  if (!schema) return false;
  const fields = (schema as any).fields;
  const key = `${collection}.${field}`;

  if (fields instanceof Map) {
    return fields.has(key) || fields.has(field);
  }

  if (typeof fields === 'object') {
    return Boolean((fields as any)[key] ?? (fields as any)[field]);
  }

  return false;
}

function detectMissingFields(schema: any, collection: string, required: string[]): string[] {
  const missing: string[] = [];
  for (const field of required) {
    if (!fieldExists(schema, collection, field)) {
      missing.push(`${collection}.${field}`);
    }
  }
  return missing;
}

function isDevEnv(baseEnv: Record<string, string | undefined>): boolean {
  const envValue = `${baseEnv?.WEBAUTHN_MODE ?? process.env.WEBAUTHN_MODE ?? ''}`.trim().toLowerCase();
  return envValue === 'dev' || envValue === 'development';
}

function diagnosticsAllowedForRequest(req: Request, baseEnv: Record<string, string | undefined>): boolean {
  const isNodeDev = `${process.env.NODE_ENV ?? ''}`.trim().toLowerCase() === 'development';
  const diagnosticsPublic = `${baseEnv?.WEBAUTHN_DIAGNOSTICS_PUBLIC ?? ''}`
    .trim()
    .toLowerCase() === 'true';
  const callerIsAdmin = Boolean((req as any)?.accountability?.admin);
  const envAllowsDiagnostics = isNodeDev || diagnosticsPublic;

  if (!envAllowsDiagnostics) return false;
  if (diagnosticsPublic) return true;
  return callerIsAdmin;
}

function expectObject(value: any, message: string) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ValidationError(message);
  }
  return value;
}

function expectString(value: any, message: string) {
  if (typeof value !== 'string') {
    throw new ValidationError(message);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw new ValidationError(message);
  }
  return trimmed;
}

const SERVICE_ACCOUNTABILITY = { admin: true };
const BUILD_INFO = loadBuildInfo();
const BUILD_FINGERPRINT = (BUILD_INFO.git_sha ?? 'unknown').slice(0, 12) || 'unknown';
const ROUTER_ID = `webauthn-router-${BUILD_INFO.package_version}-${BUILD_FINGERPRINT}`;
const EXTENSION_DIR = dirname(fileURLToPath(import.meta.url));

type ResponseMeta = {
  requestId?: string | null;
  ts: string;
  router_id: string;
  debug_id?: string | null;
  missing?: string[];
  mismatched?: string[];
};

function setBuildHeaders(res: Response) {
  try {
    if (!res.headersSent) {
      res.setHeader('X-WebAuthn-Build', BUILD_FINGERPRINT);
      res.setHeader('X-WebAuthn-Extension-Build', BUILD_FINGERPRINT);
      res.setHeader('X-WebAuthn-Version', BUILD_INFO.package_version);
    }
  } catch (error) {
    // ignore header failures
  }
}

function withResponseMeta(meta?: Partial<ResponseMeta>): ResponseMeta {
  const ts = meta?.ts ?? new Date().toISOString();
  return {
    requestId: meta?.requestId ?? null,
    debug_id: meta?.debug_id ?? null,
    ts,
    router_id: meta?.router_id ?? ROUTER_ID,
    missing: meta?.missing,
    mismatched: meta?.mismatched,
  };
}

function respondError(
  res: Response,
  status: number,
  code: string,
  message: string,
  details?: Record<string, any>,
  reason?: string | null,
  meta?: Partial<ResponseMeta>,
): void {
  const responseMeta = withResponseMeta(meta);
  const body: Record<string, any> = { ok: false, error: code, message, meta: responseMeta };
  if (reason) body.reason = reason;
  if (details) body.details = details;
  setBuildHeaders(res);
  res.status(status).json(body);
}

function respondOk(res: Response, data: Record<string, any>, meta?: Partial<ResponseMeta>): void {
  const responseMeta = withResponseMeta(meta);
  setBuildHeaders(res);
  res.json({ ok: true, ...data, meta: responseMeta });
}

function handleError(
  error: any,
  res: Response,
  next: NextFunction,
  logger: any,
  exceptions: NormalizedExceptions,
  isDev: boolean,
  meta?: {
    requestId?: string;
    route?: string;
    rpId?: string;
    hostname?: string;
    diagnosticsAllowed?: boolean;
    env?: Record<string, string | undefined>;
    debugId?: string;
  },
) {
  const { InvalidPayloadError, InvalidCredentialsError } = exceptions;
  const requestId = meta?.requestId;
  const debugId = meta?.debugId ?? randomUUID();
  const responseMeta = withResponseMeta({ requestId, debug_id: debugId });
  const baseLogMeta = { requestId, route: meta?.route, rpId: meta?.rpId, hostname: meta?.hostname, debugId };
  const diagnosticsAllowed = Boolean(meta?.diagnosticsAllowed);
  const exposeSensitiveDetails = diagnosticsAllowed;
  const exposeReason = diagnosticsAllowed;
  const logStack = () => {
    if (!logger?.error) return;
    logger.error(`[WEBAUTHN][${debugId}] stack`, { ...baseLogMeta, stack: error?.stack ?? String(error) });
  };

  if (error instanceof ConfigError) {
    logger?.[isDev ? 'warn' : 'error']?.(`[WEBAUTHN][${debugId}] configuration error`, {
      ...baseLogMeta,
      code: 'webauthn_not_configured',
      missing: error.missing ?? [],
      reason: isDev ? error.message : undefined,
    });
    logStack();
    return respondError(
      res,
      503,
      'webauthn_not_configured',
      typeof error?.message === 'string' && error.message ? error.message : 'WebAuthn not configured for this host',
      { missing: error.missing ?? [] },
      exposeReason ? error.message : null,
      responseMeta,
    );
  }

  if (error instanceof StorageUnavailableError) {
    const missing = Array.isArray(error.missing) ? error.missing : [];
    logger?.error?.(`[WEBAUTHN][${debugId}] storage unavailable`, {
      ...baseLogMeta,
      code: 'webauthn_storage_missing',
      missing,
      reason: error?.message,
    });
    logStack();
    return respondError(
      res,
      503,
      'webauthn_storage_missing',
      'WebAuthn storage unavailable',
      diagnosticsAllowed ? { missing, provisionCommand: error.provisionCommand } : undefined,
      null,
      { ...responseMeta, missing },
    );
  }

  if (error instanceof StorageSchemaError) {
    const diagnostics = toStorageDiagnostics(error.result, null, meta?.env ?? {});
    const missing = diagnostics.missing ?? diagnostics.missing_fields ?? [];
    const errorCode = 'webauthn_storage_schema_invalid';
    const message = 'WebAuthn storage schema invalid';
    const schemaMeta: ResponseMeta = {
      ...responseMeta,
      missing,
      mismatched: diagnostics.mismatched ?? diagnostics.mismatched_fields ?? [],
    };
    logger?.error?.(`[WEBAUTHN][${debugId}] storage schema invalid`, {
      ...baseLogMeta,
      code: errorCode,
      missing_collections: diagnostics.missing_collections,
      missing_fields: diagnostics.missing_fields_by_collection,
      mismatched_fields: diagnostics.mismatched_fields_by_collection,
    });
    logStack();
    return respondError(
      res,
      503,
      errorCode,
      message,
      diagnosticsAllowed
        ? {
            ...diagnostics,
            missing: diagnostics.missing_fields ?? missing,
            mismatched: diagnostics.mismatched_fields ?? [],
          }
        : { expected_schema_version: diagnostics.expected_schema_version },
      exposeReason ? message : null,
      schemaMeta,
    );
  }

  if (error instanceof WebauthnSchemaMappingError) {
    const missing = Array.isArray(error.missing) ? error.missing : [];
    logger?.error?.(`[WEBAUTHN][${debugId}] credential field mapping invalid`, {
      ...baseLogMeta,
      code: 'webauthn_storage_schema_invalid',
      missing,
      available_fields: error.available,
    });
    logStack();
    return respondError(
      res,
      503,
      'webauthn_storage_schema_invalid',
      'WebAuthn credential schema invalid',
      diagnosticsAllowed ? { missing, available_fields: error.available } : undefined,
      exposeReason ? error.message : null,
      responseMeta,
    );
  }

  if (error instanceof InvalidCredentialsError) {
    logger?.warn?.(`[WEBAUTHN][${debugId}] invalid credentials`, {
      ...baseLogMeta,
      code: 'invalid_webauthn_credentials',
      reason: isDev ? error?.message ?? null : undefined,
    });
    return respondError(
      res,
      401,
      'invalid_webauthn_credentials',
      typeof error?.message === 'string' && error.message ? error.message : 'Invalid credentials',
      { stage: 'validate' },
      isDev ? error?.message ?? null : null,
      responseMeta,
    );
  }

  if (error instanceof RegistrationInfoError) {
    logger?.warn?.(`[WEBAUTHN][${debugId}] registration info invalid`, {
      ...baseLogMeta,
      code: 'invalid_webauthn_response',
      reason: isDev ? error?.message ?? null : undefined,
    });
    logStack();
    return respondError(
      res,
      400,
      'invalid_webauthn_response',
      typeof error?.message === 'string' && error.message ? error.message : 'registrationInfo shape invalid',
      { stage: 'verify' },
      isDev ? error?.message ?? null : null,
      responseMeta,
    );
  }

  if (error instanceof BadRequestError) {
    logger?.warn?.(`[WEBAUTHN][${debugId}] bad request`, {
      ...baseLogMeta,
      code: 'invalid_webauthn_response',
      reason: isDev ? error?.message ?? null : undefined,
    });
    return respondError(
      res,
      400,
      'invalid_webauthn_response',
      typeof error?.message === 'string' && error.message ? error.message : 'Invalid WebAuthn request',
      { stage: 'validate' },
      isDev ? error?.message ?? null : null,
      responseMeta,
    );
  }

  if (error instanceof InvalidPayloadError || error instanceof ValidationError) {
    logger?.[isDev ? 'debug' : 'warn']?.(`[WEBAUTHN][${debugId}] invalid payload`, {
      ...baseLogMeta,
      code: 'invalid_webauthn_response',
      reason: isDev ? error?.message ?? null : undefined,
    });
    return respondError(
      res,
      400,
      'invalid_webauthn_response',
      typeof error?.message === 'string' && error.message ? error.message : 'Invalid WebAuthn payload',
      { stage: 'validate' },
      isDev ? error?.message ?? null : null,
      responseMeta,
    );
  }

  if (error instanceof ForbiddenError || error?.status === 403 || error?.code === 'FORBIDDEN') {
    logger?.warn?.(`[WEBAUTHN][${debugId}] permission denied`, { ...baseLogMeta, code: 'webauthn_forbidden' });
    return respondError(
      res,
      403,
      'webauthn_forbidden',
      typeof error?.message === 'string' && error.message ? error.message : 'Forbidden',
      { stage: 'validate' },
      isDev ? error?.message ?? null : null,
      responseMeta,
    );
  }

  if (error?.service === 'webauthn' || error?.service === 'authentication') {
    const serviceDetails = error?.reason
      ? diagnosticsAllowed
        ? { service: error.service, reason: error.reason, methods: error?.methods ?? undefined }
        : { service: error.service, reason: error.reason }
      : undefined;
    logger?.error?.(`[WEBAUTHN][${debugId}] service unavailable`, {
      ...baseLogMeta,
      code: 'webauthn_service_unavailable',
      error: error?.service,
      reason: error?.reason,
    });
    logStack();
    return respondError(
      res,
      503,
      'webauthn_service_unavailable',
      'WebAuthn service unavailable',
      serviceDetails,
      isDev ? error?.reason ?? error?.message ?? null : null,
      responseMeta,
    );
  }

  logger?.error?.(`[WEBAUTHN][${debugId}] internal error`, {
    ...baseLogMeta,
    code: 'webauthn_internal_error',
    reason: error?.message ?? 'internal_error',
    cause: error?.name ?? error?.constructor?.name ?? 'Error',
  });
  if (exposeReason) {
    logger?.error?.(`[WEBAUTHN][${debugId}] internal error details`, {
      ...baseLogMeta,
      router_id: ROUTER_ID,
      requestId,
      debugId,
      error_message: error?.message ?? null,
      error_stack: error?.stack ?? null,
    });
  }
  logStack();
  return respondError(
    res,
    500,
    'webauthn_internal_error',
    'Unexpected WebAuthn error',
    { cause: error?.name ?? error?.constructor?.name ?? 'Error', request_id: requestId ?? null },
    exposeReason ? error?.message ?? null : null,
    responseMeta,
  );
}

function ensureLoggedIn(req: Request, exceptions: NormalizedExceptions): { userId: string } {
  const { InvalidCredentialsError } = exceptions;
  const accountability: any = (req as any).accountability ?? {};
  const userId = accountability?.user ?? null;
  if (!userId) {
    throw new InvalidCredentialsError({ reason: 'User must be authenticated' });
  }
  return { userId: `${userId}` };
}

async function getSchemaIncludingSystem(context: ApiExtensionContext) {
  const { getSchema } = context as any;
  const fallbackSchema = (context as any)?.schema ?? null;
  if (typeof getSchema !== 'function') return fallbackSchema;
  const attempts = [
    () => getSchema({ accountability: { admin: true }, database: true, includeSystem: true } as any),
    () => getSchema({ accountability: { admin: true } } as any),
    () => getSchema(),
  ];
  for (const attempt of attempts) {
    try {
      const schema = await attempt();
      if (schema) return schema;
    } catch (error) {
      continue;
    }
  }
  return fallbackSchema;
}

async function createItemsService(
  collection: string,
  context: ApiExtensionContext,
  accountability: any,
  exceptions: NormalizedExceptions,
  options?: { includeSystem?: boolean },
) {
  const { ServiceUnavailableError } = exceptions;
  const { services, getSchema } = context as any;
  const ItemsService = services?.ItemsService;
  if (!ItemsService || typeof ItemsService !== 'function') {
    throw new ServiceUnavailableError({
      service: 'webauthn',
      reason: 'ItemsService unavailable',
    });
  }

  const schema = options?.includeSystem
    ? await getSchemaIncludingSystem(context)
    : typeof getSchema === 'function'
      ? await getSchema()
      : (await getSchemaIncludingSystem(context)) ?? (context as any).schema ?? null;

  if (!schema) {
    throw new ServiceUnavailableError({ service: 'webauthn', reason: 'Schema unavailable for ItemsService' });
  }

  return new ItemsService(collection, {
    schema,
    accountability,
    knex: (context as any).database ?? (context as any).knex,
  });
}

async function updateItemsByQueryWithFallback(
  items: any,
  query: { filter: any; limit?: number; data: Record<string, any> },
  options?: { fallbackId?: string | number | null },
): Promise<boolean> {
  if (items && typeof items.updateByQuery === 'function') {
    try {
      await items.updateByQuery(query);
      return true;
    } catch (error) {
      if (!(error instanceof TypeError)) {
        throw error;
      }
    }
  }
  if (items && typeof items.updateOne === 'function') {
    const fallbackId = options?.fallbackId ?? null;
    if (fallbackId !== null && fallbackId !== undefined) {
      await items.updateOne(fallbackId, query.data);
      return true;
    }
    if (typeof items.readByQuery === 'function') {
      const result = await items.readByQuery({ filter: query.filter, limit: 1, fields: ['id'] });
      const record = (result?.data ?? result ?? [])[0];
      const id = record?.id ?? record?.pk ?? null;
      if (id !== null && id !== undefined) {
        await items.updateOne(id, query.data);
        return true;
      }
    }
  }
  return false;
}

function isForbiddenError(error: any): boolean {
  const status = typeof error?.status === 'number' ? error.status : typeof (error as any)?.response?.status === 'number'
    ? (error as any).response.status
    : null;
  const code = typeof error?.code === 'string' ? error.code.toLowerCase() : '';
  const message = typeof error?.message === 'string' ? error.message.toLowerCase() : '';
  return status === 401 || status === 403 || code.includes('forbidden') || code.includes('permission') || message.includes('forbidden');
}

function filterRecordToKnownFields(record: Record<string, any>, fields: Set<string>) {
  const filtered: Record<string, any> = {};
  for (const [key, value] of Object.entries(record)) {
    if (!fields.has(key)) continue;
    if (value === undefined) continue;
    filtered[key] = value;
  }
  return filtered;
}

type CollectionFieldInfo = {
  name: string;
  type?: string | null;
  special?: string[] | string | null;
  interface?: string | null;
  required?: boolean;
  isPrimaryKey?: boolean;
  isM2O?: boolean;
  isO2M?: boolean;
  meta?: Record<string, any> | null;
};

const COLLECTION_FIELD_CACHE = new Map<
  string,
  { map: Map<string, CollectionFieldInfo>; expiresAt: number; collectionInfo?: Record<string, any> | null }
>();
const FIELD_CACHE_TTL_MS = 60_000;

function invalidateCollectionFieldMap(collectionName: string) {
  COLLECTION_FIELD_CACHE.delete(collectionName);
}

function normalizeFieldName(entry: any): string | null {
  const candidate =
    entry?.field ?? entry?.field_name ?? entry?.meta?.field ?? entry?.meta?.field_name ?? entry?.id ?? entry?.name;
  if (typeof candidate !== 'string') return null;
  const trimmed = candidate.trim();
  return trimmed ? trimmed : null;
}

function toCollectionFieldInfo(entry: any): CollectionFieldInfo | null {
  const name = normalizeFieldName(entry);
  if (!name) return null;
  const meta = entry?.meta && typeof entry.meta === 'object' ? entry.meta : null;
  const specialRaw = meta?.special ?? entry?.special ?? null;
  const special = Array.isArray(specialRaw)
    ? specialRaw
    : typeof specialRaw === 'string'
      ? specialRaw.split(',').map((value) => value.trim()).filter(Boolean)
      : null;
  const type = (meta?.type ?? entry?.type ?? entry?.schema?.data_type ?? entry?.schema?.type ?? null) as string | null;
  const isPrimaryKey = Boolean(entry?.schema?.is_primary_key ?? meta?.primary_key ?? meta?.is_primary_key);
  const isM2O = Boolean(special?.includes('m2o') || meta?.is_m2o);
  const isO2M = Boolean(special?.includes('o2m') || meta?.is_o2m);
  const required = Boolean(meta?.required ?? entry?.schema?.is_nullable === false);
  return { name, type, special, interface: (meta?.interface as string) ?? null, required, isPrimaryKey, isM2O, isO2M, meta };
}

async function getCollectionFieldMap(context: ApiExtensionContext, collectionName: string): Promise<Map<string, CollectionFieldInfo>> {
  const cached = COLLECTION_FIELD_CACHE.get(collectionName);
  const now = Date.now();
  if (cached && cached.expiresAt > now) {
    return cached.map;
  }

  const map = new Map<string, CollectionFieldInfo>();
  let collectionInfo: Record<string, any> | null = null;
  const schema = await getSchemaIncludingSystem(context);

  try {
    const FieldsService = (context as any)?.services?.FieldsService;
    if (FieldsService) {
      const fieldsService = new FieldsService({
        schema,
        accountability: { admin: true },
        knex: (context as any).database ?? (context as any).knex,
      });
      const entries = await fieldsService.readAll(collectionName);
      if (Array.isArray(entries)) {
        for (const entry of entries) {
          const info = toCollectionFieldInfo(entry);
          if (info) map.set(info.name, info);
        }
      }
    }
  } catch (error) {
    // Fallback below
  }

  if (map.size === 0) {
    try {
      const fieldItems = await createItemsService(
        'directus_fields',
        context,
        SERVICE_ACCOUNTABILITY,
        resolveExceptions(),
        { includeSystem: true },
      );
      const result = await fieldItems.readByQuery({
        filter: { collection: { _eq: collectionName } },
        limit: -1,
      });
      const entries: any[] = Array.isArray((result as any)?.data)
        ? (result as any).data
        : Array.isArray(result)
          ? (result as any)
          : [];
      for (const entry of entries) {
        const info = toCollectionFieldInfo(entry);
        if (info) map.set(info.name, info);
      }
    } catch (error) {
      // leave map empty; caller can react to schema issues
    }
  }

  try {
    const collectionItems = await createItemsService(
      'directus_collections',
      context,
      SERVICE_ACCOUNTABILITY,
      resolveExceptions(),
      { includeSystem: true },
    );
    const result = await collectionItems.readByQuery({
      filter: { collection: { _eq: collectionName } },
      limit: 1,
    });
    const row = (result?.data ?? result ?? [])[0];
    collectionInfo = row && typeof row === 'object' ? row : null;
  } catch (error) {
    // Non-fatal
  }

  COLLECTION_FIELD_CACHE.set(collectionName, { map, expiresAt: now + FIELD_CACHE_TTL_MS, collectionInfo });
  return map;
}

type CredentialRecordDebug = {
  includedFields: string[];
  missingRequired: string[];
  droppedUnknown: string[];
  typeConflicts: string[];
};

function coerceValueForField(info: CollectionFieldInfo | undefined, value: any): { value: any; conflict?: string } {
  if (!info) return { value };
  const type = `${info.type ?? ''}`.toLowerCase();
  const special = Array.isArray(info.special) ? info.special.map((s) => s.toLowerCase()) : [];
  if (value === undefined) return { value: undefined };
  if (value === null) return { value: null };

  const asNumber = () => {
    const num = Number(value);
    if (Number.isFinite(num)) return { value: num };
    return { value: value, conflict: `${info.name} expects number` };
  };

  if (type.includes('int') || type.includes('decimal') || type.includes('float') || type.includes('numeric')) {
    return asNumber();
  }
  if (type.includes('uuid') || special.includes('uuid')) {
    if (typeof value === 'string') return { value };
    return { value, conflict: `${info.name} expects uuid string` };
  }
  if (type.includes('bool')) {
    return { value: Boolean(value) };
  }
  if (type.includes('json')) {
    if (typeof value === 'object') return { value };
    try {
      const parsed = JSON.parse(String(value));
      return { value: parsed };
    } catch (error) {
      return { value, conflict: `${info.name} expects json` };
    }
  }
  if (type.includes('date') || type.includes('time')) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return { value, conflict: `${info.name} expects datetime string` };
    }
    return { value: date.toISOString() };
  }
  if (type.includes('string') || type.includes('text')) {
    if (typeof value === 'string') return { value };
    return { value: JSON.stringify(value) };
  }

  return { value };
}

function buildCredentialRecord(
  fieldMap: Map<string, CollectionFieldInfo>,
  extracted: {
    credentialIdB64u: string;
    publicKeyB64u: string;
    counter: number;
    transports: any;
    coseAlg?: number | null;
    aaguid: string | null;
    deviceType: string | null;
    backedUp: boolean | null;
    userAgent?: string | null;
    origin?: string | null;
    rpId?: string | null;
    lastUsedAt?: string | null;
  },
  userId: string,
  config: WebAuthnConfig,
  requestMeta: { nickname: string | null; origin?: string | null; userAgent?: string | null; lastUsedAt?: string | null },
  webauthnMap: WebauthnCredentialsFieldMap,
): { record: Record<string, any>; debug: CredentialRecordDebug; credentialIdField: string | null } {
  const allowedContractFields = new Set<string>(
    [
      ...credentialsFieldNames,
      'created_at',
      'updated_at',
      'rp_id',
      'credential_uuid',
      'cose_alg',
      webauthnMap.credentialIdField,
      webauthnMap.publicKeyField,
      webauthnMap.userField,
      webauthnMap.signCountField,
      webauthnMap.coseAlgField,
      webauthnMap.transportsField,
      webauthnMap.nicknameField,
      webauthnMap.createdAtField,
      webauthnMap.updatedAtField,
      webauthnMap.lastUsedAtField,
      webauthnMap.aaguidField,
      webauthnMap.deviceTypeField,
      webauthnMap.backedUpField,
      webauthnMap.originField,
      webauthnMap.userAgentField,
    ].filter((value): value is string => Boolean(value)),
  );
  const knownFields = new Set(Array.from(fieldMap.keys()).filter((name) => allowedContractFields.has(name) || name === 'id'));
  const record: Record<string, any> = {};
  const debug: CredentialRecordDebug = { includedFields: [], missingRequired: [], droppedUnknown: [], typeConflicts: [] };

  const userFieldName = webauthnMap.userField ?? (fieldMap.has('user') ? 'user' : fieldMap.has('user_id') ? 'user_id' : null);
  if (userFieldName) {
    const userField = fieldMap.get(userFieldName);
    const userFieldType = `${userField?.type ?? ''}`.toLowerCase();
    if (userFieldType.includes('int') || userFieldType.includes('bigint')) {
      const numericUserId = Number(userId);
      if (!Number.isFinite(numericUserId)) {
        throw new PersistError(
          'user field expects integer but user id is not numeric',
          'PERSIST_SCHEMA_MISMATCH',
          { field: userFieldName, expected: 'integer', provided: userId },
        );
      }
      record[userFieldName] = numericUserId;
    } else {
      record[userFieldName] = userId;
    }
    debug.includedFields.push(userFieldName);
  } else {
    debug.missingRequired.push('user');
  }

  const nowIso = new Date().toISOString();

  const baseValues: Record<string, any> = {};
  baseValues[webauthnMap.credentialIdField] = extracted.credentialIdB64u;
  baseValues[webauthnMap.publicKeyField] = extracted.publicKeyB64u;
  if (webauthnMap.signCountField) {
    baseValues[webauthnMap.signCountField] = Number.isFinite(extracted.counter) ? extracted.counter : 0;
  }
  if (webauthnMap.coseAlgField) {
    const alg =
      typeof extracted.coseAlg === 'number' && Number.isFinite(extracted.coseAlg)
        ? extracted.coseAlg
        : -7;
    baseValues[webauthnMap.coseAlgField] = alg;
  }
  if (webauthnMap.transportsField) {
    baseValues[webauthnMap.transportsField] = extracted.transports ?? [];
  }
  if (webauthnMap.aaguidField) {
    baseValues[webauthnMap.aaguidField] = extracted.aaguid ?? null;
  }
  if (webauthnMap.deviceTypeField) {
    baseValues[webauthnMap.deviceTypeField] = extracted.deviceType ?? null;
  }
  if (webauthnMap.backedUpField) {
    baseValues[webauthnMap.backedUpField] = extracted.backedUp ?? null;
  }
  if (webauthnMap.nicknameField) {
    baseValues[webauthnMap.nicknameField] = requestMeta.nickname ?? 'Passkey';
  }
  if (knownFields.has('rp_id')) {
    baseValues.rp_id = config.rpId ?? extracted.rpId ?? null;
  }
  if (webauthnMap.userAgentField) {
    baseValues[webauthnMap.userAgentField] = extracted.userAgent ?? requestMeta.userAgent ?? null;
  }
  if (webauthnMap.originField) {
    baseValues[webauthnMap.originField] = extracted.origin ?? requestMeta.origin ?? null;
  }
  if (webauthnMap.lastUsedAtField) {
    baseValues[webauthnMap.lastUsedAtField] = extracted.lastUsedAt ?? requestMeta.lastUsedAt ?? nowIso;
  }

  if (webauthnMap.createdAtField && knownFields.has(webauthnMap.createdAtField)) {
    baseValues[webauthnMap.createdAtField] = nowIso;
  }
  if (webauthnMap.updatedAtField && knownFields.has(webauthnMap.updatedAtField)) {
    baseValues[webauthnMap.updatedAtField] = nowIso;
  }

  if (!knownFields.has(webauthnMap.credentialIdField)) {
    debug.missingRequired.push(webauthnMap.credentialIdField);
  }
  if (!knownFields.has(webauthnMap.publicKeyField)) {
    debug.missingRequired.push(webauthnMap.publicKeyField);
  }

  if (knownFields.has('credential_uuid')) {
    baseValues.credential_uuid = randomUUID();
  }

  let credentialIdField: string | null = null;

  for (const [key, value] of Object.entries(baseValues)) {
    if (!knownFields.has(key)) {
      debug.droppedUnknown.push(key);
      continue;
    }
    const fieldInfo = fieldMap.get(key);
    const { value: coerced, conflict } = coerceValueForField(fieldInfo, value);
    if (conflict) debug.typeConflicts.push(conflict);
    record[key] = coerced;
    debug.includedFields.push(key);
    if (key === webauthnMap.credentialIdField) credentialIdField = webauthnMap.credentialIdField;
  }

  for (const [name, info] of fieldMap.entries()) {
    if (!info.required || info.isPrimaryKey) continue;
    if (record[name] === undefined || record[name] === null || record[name] === '') {
      debug.missingRequired.push(name);
    }
  }

  return { record, debug, credentialIdField };
}

function extractFieldsFromSchema(schema: any, collection: string): Set<string> {
  const names = new Set<string>();
  if (!schema || typeof schema !== 'object') return names;

  const fields = (schema as any).fields;
  const prefix = `${collection}.`;
  if (fields instanceof Map) {
    for (const key of fields.keys()) {
      if (typeof key !== 'string') continue;
      if (key.startsWith(prefix)) {
        names.add(key.slice(prefix.length));
      } else if (!key.includes('.')) {
        names.add(key);
      }
    }
  } else if (fields && typeof fields === 'object') {
    for (const key of Object.keys(fields)) {
      if (key.startsWith(prefix)) {
        names.add(key.slice(prefix.length));
      } else if (!key.includes('.')) {
        names.add(key);
      }
    }
  }
  return names;
}

async function getFieldsForCollection(
  collection: string,
  context: ApiExtensionContext,
  exceptions: NormalizedExceptions,
): Promise<Set<string>> {
  const schema = await getSchemaIncludingSystem(context);
  const schemaFields = extractFieldsFromSchema(schema, collection);
  if (schemaFields.size > 0) return schemaFields;

  try {
    const FieldsService = (context as any)?.services?.FieldsService;
    if (FieldsService) {
      const service = new FieldsService({
        schema,
        accountability: SERVICE_ACCOUNTABILITY,
        knex: (context as any).database ?? (context as any).knex,
      });
      const result = await service.readByQuery({
        filter: { collection: { _eq: collection } },
        limit: -1,
        fields: ['field', 'field_name', 'id'],
      });
      const entries: any[] = Array.isArray((result as any)?.data)
        ? (result as any).data
        : Array.isArray(result)
          ? (result as any)
          : [];
      const names = new Set<string>();
      for (const entry of entries) {
        const candidate = (entry?.field ?? entry?.field_name ?? entry?.id ?? '') as any;
        if (typeof candidate === 'string' && candidate.trim()) names.add(candidate.trim());
      }
      if (names.size > 0) return names;
    }
  } catch (error) {
    // Fall through to ItemsService fallback below.
  }

  try {
    const fieldService = await createItemsService(
      'directus_fields',
      context,
      SERVICE_ACCOUNTABILITY,
      exceptions,
      { includeSystem: true },
    );
    const result = await fieldService.readByQuery({
      filter: { collection: { _eq: collection } },
      limit: -1,
      fields: ['field', 'field_name', 'id'],
    });
    const entries: any[] = Array.isArray((result as any)?.data) ? (result as any).data : Array.isArray(result) ? (result as any) : [];
    const names = new Set<string>();
    for (const entry of entries) {
      const candidate = (entry?.field ?? entry?.field_name ?? entry?.id ?? '') as any;
      if (typeof candidate === 'string' && candidate.trim()) names.add(candidate.trim());
    }
    if (names.size > 0) return names;
  } catch (error) {
    // Swallow and fall through; persistence layer will surface schema issues.
  }

  return new Set<string>();
}

async function createUsersLookup(
  context: ApiExtensionContext,
  exceptions: NormalizedExceptions,
  accountability?: any,
) {
  const { ServiceUnavailableError } = exceptions;
  const { services } = context as any;
  const schema = (await getSchemaIncludingSystem(context)) ?? (await (context as any).getSchema?.());
  if (!schema) throw new ServiceUnavailableError({ service: 'webauthn', reason: 'Schema unavailable for users' });
  const UsersService = services?.UsersService ?? services?.UsersService;
  if (UsersService && typeof UsersService === 'function') {
    return new UsersService({ schema, accountability: accountability ?? { admin: true } });
  }
  const ItemsService = services?.ItemsService;
  if (!ItemsService || typeof ItemsService !== 'function') {
    throw new ServiceUnavailableError({ service: 'webauthn', reason: 'UsersService unavailable' });
  }
  return new ItemsService('directus_users', {
    schema,
    accountability: accountability ?? { admin: true },
    knex: (context as any).database ?? (context as any).knex,
  });
}

async function loadUser(
  context: ApiExtensionContext,
  userId: string,
  accountability: any,
  exceptions: NormalizedExceptions,
) {
  const normalizedAccountability =
    accountability &&
    (typeof accountability !== 'object' ||
      Boolean((accountability as any).admin) ||
      Boolean((accountability as any).user))
      ? accountability
      : SERVICE_ACCOUNTABILITY;
  const usersService = await createUsersLookup(context, exceptions, normalizedAccountability);
  return usersService.readOne(userId, { fields: ['id', 'email', 'first_name', 'last_name'] });
}

function normalizeCredentialIdString(value: any): string | null {
  const text = typeof value === 'string' && value.trim() ? value.trim() : toBase64Url(value);
  if (!text) return null;
  return text.replace(/=+$/, '');
}

function credentialIdsMatch(a: any, b: any): boolean {
  const left = normalizeCredentialIdString(a);
  const right = normalizeCredentialIdString(b);
  if (!left || !right) return false;
  if (left === right) return true;
  try {
    const lbuf = isoBase64URL.toBuffer(left);
    const rbuf = isoBase64URL.toBuffer(right);
    if (lbuf.byteLength !== rbuf.byteLength) return false;
    for (let i = 0; i < lbuf.byteLength; i += 1) {
      if (lbuf[i] !== rbuf[i]) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function toCredentialIdPrefix(id: string | null, length = 16): string | null {
  if (!id) return null;
  return id.slice(0, length);
}

function projectCredential(
  row: any,
  fieldMap: WebauthnCredentialsFieldMap,
): StoredCredential | null {
  if (!row) return null;
  const base: StoredCredential = {
    id: (row as any).id ?? null,
    credential_uuid: (row as any).credential_uuid ?? null,
    credential_id: (row as any)[fieldMap.credentialIdField],
    public_key: (row as any)[fieldMap.publicKeyField],
    user: `${(row as any)[fieldMap.userField] ?? ''}`,
    sign_count:
      fieldMap.signCountField && (row as any)[fieldMap.signCountField] !== undefined
        ? (row as any)[fieldMap.signCountField]
        : null,
    cose_alg:
      fieldMap.coseAlgField && (row as any)[fieldMap.coseAlgField] !== undefined
        ? (row as any)[fieldMap.coseAlgField]
        : null,
    transports:
      fieldMap.transportsField && (row as any)[fieldMap.transportsField] !== undefined
        ? (row as any)[fieldMap.transportsField]
        : null,
    aaguid:
      fieldMap.aaguidField && (row as any)[fieldMap.aaguidField] !== undefined
        ? (row as any)[fieldMap.aaguidField]
        : null,
    device_type:
      fieldMap.deviceTypeField && (row as any)[fieldMap.deviceTypeField] !== undefined
        ? (row as any)[fieldMap.deviceTypeField]
        : null,
    backed_up:
      fieldMap.backedUpField && (row as any)[fieldMap.backedUpField] !== undefined
        ? (row as any)[fieldMap.backedUpField]
        : null,
    nickname:
      fieldMap.nicknameField && (row as any)[fieldMap.nicknameField] !== undefined
        ? (row as any)[fieldMap.nicknameField]
        : null,
    origin:
      fieldMap.originField && (row as any)[fieldMap.originField] !== undefined
        ? (row as any)[fieldMap.originField]
        : null,
    user_agent:
      fieldMap.userAgentField && (row as any)[fieldMap.userAgentField] !== undefined
        ? (row as any)[fieldMap.userAgentField]
        : null,
    created_at:
      fieldMap.createdAtField && (row as any)[fieldMap.createdAtField] !== undefined
        ? (row as any)[fieldMap.createdAtField]
        : null,
    updated_at:
      fieldMap.updatedAtField && (row as any)[fieldMap.updatedAtField] !== undefined
        ? (row as any)[fieldMap.updatedAtField]
        : null,
    last_used_at:
      fieldMap.lastUsedAtField && (row as any)[fieldMap.lastUsedAtField] !== undefined
        ? (row as any)[fieldMap.lastUsedAtField]
        : null,
  };

  if (!base.credential_id || !base.public_key || !base.user) return null;
  return base;
}

function buildCredentialFieldList(fieldMap: WebauthnCredentialsFieldMap): string[] {
  const fields = new Set<string>([
    'id',
    'credential_uuid',
    fieldMap.credentialIdField,
    fieldMap.publicKeyField,
    fieldMap.userField,
    fieldMap.signCountField,
    fieldMap.coseAlgField,
    fieldMap.transportsField,
    fieldMap.nicknameField,
    fieldMap.createdAtField,
    fieldMap.updatedAtField,
    fieldMap.lastUsedAtField,
    fieldMap.aaguidField,
    fieldMap.deviceTypeField,
    fieldMap.backedUpField,
    fieldMap.originField,
    fieldMap.userAgentField,
  ]);

  return Array.from(fields).filter((value): value is string => Boolean(value));
}

async function listCredentials(
  context: ApiExtensionContext,
  collection: string,
  userId: string,
  accountability: any,
  exceptions: NormalizedExceptions,
  fieldMapResult?: WebauthnCredentialsFieldMapResult,
): Promise<StoredCredential[]> {
  const mapResult = fieldMapResult ?? (await getWebauthnCredentialsFieldMap(context, collection));
  const fieldMap = mapResult.fieldMap;
  const items = await createItemsService(collection, context, accountability ?? SERVICE_ACCOUNTABILITY, exceptions);
  const fields = buildCredentialFieldList(fieldMap);
  const result = await items.readByQuery({
    filter: { [fieldMap.userField]: { _eq: userId } },
    limit: 100,
    fields,
  });
  const rows = (result?.data ?? result ?? []) as any[];
  return rows.map((row) => projectCredential(row, fieldMap)).filter(Boolean) as StoredCredential[];
}

async function saveChallenge(
  context: ApiExtensionContext,
  accountability: any,
  collection: string,
  payload: {
    userId: string | null;
    type: ChallengeType;
    flow?: ChallengeFlow;
    challenge: string;
    rpId: string;
    origins: string[];
    allowedCredentialIds?: string[];
    attemptId?: string;
    ttlMs: number;
  },
  exceptions: NormalizedExceptions,
) {
  const items = await createItemsService(collection, context, accountability ?? SERVICE_ACCOUNTABILITY, exceptions);
  const now = Date.now();
  const ttlMs = typeof payload.ttlMs === 'number' && Number.isFinite(payload.ttlMs)
    ? payload.ttlMs
    : NaN;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new ValidationError('ttlMs is required for challenge persistence');
  }
  const expiresAt = new Date(now + ttlMs).toISOString();
  const origin = payload.origins?.[0] ?? null;
  const challengeId = payload.attemptId ?? nanoid();
  const fallbackRpId =
    payload.rpId ??
    (context as any)?.env?.WEBAUTHN_RP_ID ??
    process.env.WEBAUTHN_RP_ID ??
    (origin ? (() => { try { return new URL(origin).hostname; } catch { return null; } })() : null);
  const rpId = payload.rpId ?? fallbackRpId;
  const challengeRecord = {
    attemptId: payload.attemptId,
    challenge: payload.challenge,
    rpId,
    origins: payload.origins,
    allowedCredentialIds: payload.allowedCredentialIds ?? [],
    type: payload.type,
    flow: payload.flow ?? (payload.type === 'registration' ? 'registration' : 'auth'),
    userId: payload.userId,
    challengeId,
    createdAt: new Date(now).toISOString(),
  };
  const dbRecord = {
    challenge_id: challengeId,
    user: payload.userId,
    type: payload.type,
    challenge: JSON.stringify(challengeRecord),
    rp_id: rpId,
    origin,
    expires_at: expiresAt,
    created_at: new Date(now).toISOString(),
    used_at: null,
  };

  await items.createOne(dbRecord);

  const sink = (context as any)?.__challengeSink;
  if (Array.isArray(sink)) {
    sink.push(dbRecord);
  }
  if ((context as any)) {
    (context as any).__lastChallenge = dbRecord;
  }
}

function parseStoredChallenge(row: StoredChallenge) {
  const fallback = {
    attemptId: row.challenge_id ?? row.id,
    challenge: row.challenge,
    rpId: row.rp_id ?? null,
    origins: row.origin ? [row.origin] : (null as string[] | null),
    allowedCredentialIds: [] as string[],
    type: row.type,
    flow: null as ChallengeFlow | null,
    userId: row.user === null || typeof row.user === 'undefined' ? null : `${row.user}`,
    publicKey: null as any,
  };

  if (!row.challenge) return fallback;
  try {
    const parsedRaw = typeof row.challenge === 'string' ? JSON.parse(row.challenge) : row.challenge;
    if (!parsedRaw || typeof parsedRaw !== 'object') return fallback;
    const parsed = parsedRaw as any;
    const challenge = typeof parsed.challenge === 'string' ? parsed.challenge : fallback.challenge;
    const rpId = typeof parsed.rpId === 'string' ? parsed.rpId : fallback.rpId;
    const origins = Array.isArray(parsed.origins) ? parsed.origins.filter((v: any) => typeof v === 'string') : fallback.origins;
    const allowedCredentialIds = Array.isArray(parsed.allowedCredentialIds)
      ? parsed.allowedCredentialIds.filter((v: any) => typeof v === 'string')
      : fallback.allowedCredentialIds;
    const publicKey = parsed && typeof parsed === 'object' ? (parsed as any).publicKey ?? null : null;
    const attemptId = typeof parsed.attemptId === 'string' ? parsed.attemptId : fallback.attemptId;
    const flow = typeof parsed.flow === 'string' ? (parsed.flow as ChallengeFlow) : fallback.flow;
    const parsedUserId =
      parsed.userId === null || typeof parsed.userId === 'undefined'
        ? fallback.userId
        : `${parsed.userId}`;
    return {
      attemptId,
      challenge,
      rpId,
      origins,
      allowedCredentialIds,
      type: row.type,
      flow,
      userId: parsedUserId,
      publicKey,
    };
  } catch (error) {
    return fallback;
  }
}

function normalizeStoredChallenge(
  row: StoredChallenge,
  parsed: ReturnType<typeof parseStoredChallenge>,
  InvalidPayloadError: new (args: { reason: string }) => Error,
): ReturnType<typeof parseStoredChallenge> {
  const issues: string[] = [];
  const challenge = typeof parsed.challenge === 'string' ? parsed.challenge.trim() : '';
  const rpId = typeof parsed.rpId === 'string' ? parsed.rpId.trim() : '';
  const origins = Array.isArray(parsed.origins)
    ? parsed.origins.filter((origin) => typeof origin === 'string' && origin.trim())
    : [];
  const flowValue = typeof parsed.flow === 'string' ? parsed.flow.trim() : '';
  const flow: ChallengeFlow | null =
    flowValue === 'auth' || flowValue === 'drytest' || flowValue === 'registration' ? flowValue : null;
  const userId =
    parsed.userId === null || typeof parsed.userId === 'undefined'
      ? row.user === null || typeof row.user === 'undefined'
        ? null
        : `${row.user}`
      : parsed.userId;
  const expiresAt = row.expires_at ?? null;
  const expiresMs = expiresAt ? Date.parse(expiresAt) : NaN;

  if (!challenge) issues.push('challenge');
  if (!origins.length) issues.push('origins');
  if (!rpId) issues.push('rpId');
  if (!userId) issues.push('user');
  if (!expiresAt || Number.isNaN(expiresMs)) issues.push('expires_at');
  if (!Number.isNaN(expiresMs) && expiresMs <= Date.now()) {
    throw new InvalidPayloadError({ reason: 'WebAuthn challenge expired' });
  }

  if (issues.length) {
    throw new InvalidPayloadError({ reason: `WebAuthn challenge missing required fields: ${issues.join(', ')}` });
  }

  return {
    ...parsed,
    challenge,
    rpId,
    origins,
    flow,
    userId,
  };
}

async function consumeChallenge(
  context: ApiExtensionContext,
  accountability: any,
  userId: string | null,
  type: ChallengeType,
  collection: string,
  exceptions: NormalizedExceptions,
  attemptId?: string | null,
  expectedFlow?: ChallengeFlow,
): Promise<{ row: StoredChallenge; parsed: ReturnType<typeof parseStoredChallenge> }> {
  const { InvalidPayloadError } = exceptions;
  const items = await createItemsService(collection, context, accountability ?? SERVICE_ACCOUNTABILITY, exceptions);
  let row: StoredChallenge | undefined;

  if (attemptId) {
    try {
      const attemptResult = await items.readByQuery({
        filter: { challenge_id: { _eq: attemptId } },
        limit: 1,
        fields: ['id', 'challenge_id', 'challenge', 'type', 'user', 'rp_id', 'origin', 'expires_at', 'used_at'],
      });
      row = (attemptResult?.data ?? attemptResult ?? [])[0] as StoredChallenge | undefined;
    } catch (error: any) {
      row = undefined;
    }

    if (!row) {
      throw new InvalidPayloadError({ reason: 'No pending WebAuthn challenge for this attempt' });
    }
  }

  if (!row && userId) {
    const result = await items.readByQuery({
      filter: {
        user: { _eq: userId },
        type: { _eq: type },
        expires_at: { _gte: new Date().toISOString() },
        used_at: { _null: true },
      },
      sort: ['-created_at'],
      limit: 1,
      fields: ['id', 'challenge_id', 'challenge', 'type', 'user', 'rp_id', 'origin', 'expires_at', 'used_at'],
    });
    row = (result?.data ?? result ?? [])[0] as StoredChallenge | undefined;
  }

  if (row?.expires_at) {
    const expiresAt = new Date(row.expires_at);
    if (Number.isFinite(expiresAt.valueOf()) && expiresAt <= new Date()) {
      throw new InvalidPayloadError({ reason: 'WebAuthn challenge expired' });
    }
  }

  if (!row || !row.challenge) {
    throw new InvalidPayloadError({ reason: 'No pending WebAuthn challenge for this user' });
  }

  if (row.used_at) {
    throw new InvalidPayloadError({ reason: 'WebAuthn challenge already used' });
  }

  if (userId && row.user && `${row.user}` !== `${userId}`) {
    throw new InvalidPayloadError({ reason: 'Challenge was issued for a different user' });
  }

  if (!userId && !attemptId) {
    throw new InvalidPayloadError({ reason: 'Attempt id is required for discoverable credentials' });
  }

  if (!row.challenge_id) {
    throw new InvalidPayloadError({ reason: 'Challenge identifier missing for this record' });
  }

  const usedAt = new Date().toISOString();
  try {
    await items.deleteByQuery({
      filter: {
        _or: [
          { challenge_id: { _eq: `${row.challenge_id}` } },
          {
            id: {
              _eq: typeof row.id === 'number' ? row.id : Number.isNaN(Number(row.id)) ? row.id : Number(row.id),
            },
          },
        ],
      },
      limit: 1,
    });
  } catch (error) {
    try {
      await updateItemsByQueryWithFallback(
        items,
        {
          filter: { challenge_id: { _eq: row.challenge_id } },
          limit: 1,
          data: { used_at: usedAt },
        },
        { fallbackId: row?.id ?? null },
      );
    } catch {
      // ignore fallback update failures
    }
  }
  row.used_at = usedAt;
  const parsed = parseStoredChallenge(row);
  const normalized = normalizeStoredChallenge(row, parsed, InvalidPayloadError);
  if (expectedFlow && normalized.flow && normalized.flow !== expectedFlow) {
    throw new InvalidPayloadError({ reason: 'WebAuthn challenge flow mismatch' });
  }
  return { row, parsed: normalized };
}

async function deleteChallengeById(
  context: ApiExtensionContext,
  accountability: any,
  collection: string,
  challengeId: string | number | null,
  exceptions: NormalizedExceptions,
  logger?: any,
) {
  if (!challengeId) return;
  try {
    const items = await createItemsService(collection, context, accountability ?? SERVICE_ACCOUNTABILITY, exceptions);
    await items.deleteByQuery({
      filter: {
        _or: [
          { challenge_id: { _eq: `${challengeId}` } },
          { id: { _eq: typeof challengeId === 'number' ? challengeId : Number.isNaN(Number(challengeId)) ? challengeId : Number(challengeId) } },
        ],
      },
      limit: 1,
    });
  } catch (error) {
    logger?.warn?.('[WEBAUTHN] challenge delete failed', {
      challenge_id: challengeId,
      error: error?.message ?? String(error),
    });
  }
}

async function cleanupChallenges(
  context: ApiExtensionContext,
  collection: string,
  exceptions: NormalizedExceptions,
  logger?: any,
  now: Date = new Date(),
) {
  const cutoffExpired = now.toISOString();
  const cutoffUsed = new Date(now.getTime() - 5 * 60 * 1000).toISOString();
  try {
    const items = await createItemsService(collection, context, SERVICE_ACCOUNTABILITY, exceptions);
    await items.deleteByQuery({
      filter: {
        _or: [
          { expires_at: { _lt: cutoffExpired } },
          { _and: [{ used_at: { _lt: cutoffUsed } }, { used_at: { _nnull: true } }] },
        ],
      },
    });
  } catch (error) {
    logger?.warn?.('[WEBAUTHN] challenge cleanup failed', {
      error: error?.message ?? String(error),
      cutoffExpired,
      cutoffUsed,
    });
  }
}

async function findCredentialById(
  context: ApiExtensionContext,
  collection: string,
  accountability: any,
  credentialId: string,
  exceptions: NormalizedExceptions,
  fieldMapResult?: WebauthnCredentialsFieldMapResult,
): Promise<StoredCredential | null> {
  const mapResult = fieldMapResult ?? (await getWebauthnCredentialsFieldMap(context, collection));
  const fieldMap = mapResult.fieldMap;
  const items = await createItemsService(collection, context, accountability ?? SERVICE_ACCOUNTABILITY, exceptions);
  const fields = buildCredentialFieldList(fieldMap);
  const result = await items.readByQuery({
    filter: { [fieldMap.credentialIdField]: { _eq: credentialId } },
    limit: 1,
    fields,
  });
  const row = (result?.data ?? result ?? [])[0] as any;
  return projectCredential(row, fieldMap);
}

function toAllowCredentials(credentials: StoredCredential[]) {
  const allow = [] as { id: string; transports?: string[] }[];
  for (const credential of credentials) {
    if (!credential?.credential_id) continue;
    const idText = normalizeCredentialIdString(credential.credential_id);
    if (!idText || !/^[A-Za-z0-9_-]+$/.test(idText)) continue;
    allow.push({
      id: idText,
      transports: Array.isArray(credential.transports) ? credential.transports : undefined,
    });
  }
  return allow;
}

function toCredentialType(deviceType: string | null | undefined) {
  if (deviceType === 'singleDevice') return 'platform';
  if (deviceType === 'multiDevice') return 'cross-platform';
  return 'unknown';
}

function summarizeUser(user: any) {
  return {
    id: `${user?.id ?? ''}`,
    email: typeof user?.email === 'string' ? user.email : null,
    name:
      typeof user?.email === 'string'
        ? user.email
        : [user?.first_name, user?.last_name].filter((v) => typeof v === 'string' && v.trim()).join(' ').trim() || `${user?.id}`,
  };
}

function toArrayBufferView(buffer: Buffer | Uint8Array | ArrayBuffer): Uint8Array<ArrayBuffer> {
  const view = buffer instanceof Uint8Array ? Uint8Array.from(buffer) : new Uint8Array(buffer as ArrayBuffer);
  const normalizedBuffer = new ArrayBuffer(view.byteLength);
  const normalized = new Uint8Array(normalizedBuffer);
  normalized.set(view);
  return normalized as Uint8Array<ArrayBuffer>;
}

function normalizeToBuffer(value: any, label: string): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value instanceof ArrayBuffer) return Buffer.from(new Uint8Array(value));
  if (value && typeof value === 'object' && typeof (value as any).buffer === 'object') {
    try {
      const view = new Uint8Array(
        (value as any).buffer,
        (value as any).byteOffset ?? 0,
        (value as any).byteLength ?? (value as any).buffer?.byteLength ?? undefined,
      );
      return Buffer.from(view);
    } catch (error) {
      // Fall through to string handling below
    }
  }
  if (value && typeof value === 'object' && typeof (value as any).byteLength === 'number') {
    try {
      return Buffer.from(new Uint8Array(value as ArrayBufferLike));
    } catch (error) {
      // Fall through to string handling below
    }
  }
  if (typeof value === 'string') {
    try {
      const parsed = isoBase64URL.toBuffer(value);
      return Buffer.isBuffer(parsed) ? parsed : Buffer.from(parsed);
    } catch (error) {
      throw new RegistrationInfoError(`${label} must be base64url encoded`);
    }
  }
  throw new RegistrationInfoError(`${label} missing or invalid`);
}

function toUint8ArrayFromBase64Url(value: string, label = 'credential_id'): Uint8Array<ArrayBuffer> {
  const buffer = normalizeToBuffer(value, label);
  return toArrayBufferView(buffer);
}

function toSafeCredentialId(buffer: Buffer | Uint8Array | ArrayBuffer | string) {
  const normalized = normalizeToBuffer(buffer, 'credential_id');
  const safeView = toArrayBufferView(normalized);
  return isoBase64URL.fromBuffer(safeView);
}

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

function isBase64UrlString(value: string) {
  return BASE64URL_PATTERN.test(value) && value.length > 8 && value.length < 512;
}

function isUniqueConstraintError(error: any): boolean {
  const message = typeof error?.message === 'string' ? error.message.toLowerCase() : '';
  const code = typeof (error as any)?.code === 'string' ? (error as any).code.toLowerCase() : '';
  const extensionCode = typeof (error as any)?.extensions?.code === 'string'
    ? (error as any).extensions.code.toLowerCase()
    : '';
  const status = typeof (error as any)?.status === 'number' ? (error as any).status : null;

  return (
    message.includes('unique constraint') ||
    message.includes('duplicate key') ||
    message.includes('not unique') ||
    code.includes('unique') ||
    code.includes('duplicate') ||
    extensionCode.includes('unique') ||
    extensionCode.includes('duplicate') ||
    status === 409
  );
}

async function findUserByEmail(context: ApiExtensionContext, email: string, accountability: any, exceptions: NormalizedExceptions) {
  const normalized = email.trim().toLowerCase();
  if (!normalized) return null;
  const candidates = Array.from(new Set([email.trim(), normalized].filter(Boolean)));
  const usersService = await createUsersLookup(context, exceptions, accountability ?? { admin: true });
  const result = await usersService.readByQuery({
    filter: { email: { _in: candidates } },
    limit: 1,
    fields: ['id', 'email', 'first_name', 'last_name'],
  });
  const row = (result?.data ?? result ?? [])[0];
  return row ?? null;
}

async function insertCredentialWithKnex(
  context: ApiExtensionContext,
  collection: string,
  record: Record<string, any>,
): Promise<Record<string, any> | null> {
  const knex = (context as any)?.database ?? (context as any)?.knex ?? (context as any)?.databaseClient ?? null;
  if (!knex || typeof knex !== 'function') return null;
  try {
    const query = (knex as any)(collection).insert(record);
    const result = await (typeof query.returning === 'function' ? query.returning('*') : query);
    if (Array.isArray(result) && result.length > 0) {
      return result[0] as Record<string, any>;
    }
    if (result && typeof result === 'object') return result as Record<string, any>;
    if (result !== undefined && result !== null) return { id: result } as Record<string, any>;
  } catch (error) {
    return null;
  }
  return null;
}

async function saveCredential(
  context: ApiExtensionContext,
  collection: string,
  userId: string,
  payload: {
    credentialIdB64u: string;
    publicKeyB64u: string;
    counter: number;
    transports: any;
    coseAlg?: number | null;
    aaguid: string | null;
    deviceType: string | null;
    backedUp: boolean | null;
    userAgent?: string | null;
    origin?: string | null;
    rpId?: string | null;
    lastUsedAt?: string | null;
  },
  nickname: string | null,
  exceptions: NormalizedExceptions,
  options: { debugPersist?: boolean; config: WebAuthnConfig },
): Promise<{ record: StoredCredential; debug: CredentialRecordDebug; credentialIdField: string | null }> {
  const items = await createItemsService(
    collection,
    context,
    SERVICE_ACCOUNTABILITY,
    exceptions,
    { includeSystem: true },
  );

  const fieldMap = await getCollectionFieldMap(context, collection);
  const webauthnMapResult = await getWebauthnCredentialsFieldMap(context, collection);
  const webauthnMap = webauthnMapResult.fieldMap;
  if (fieldMap.size === 0) {
    throw new PersistError('Schema unavailable for credential persistence', 'PERSIST_SCHEMA_MISMATCH', {
      missing_required_fields: ['credential_id', 'public_key', 'user'],
    });
  }

  const recordBuild = buildCredentialRecord(
    fieldMap,
    payload,
    userId,
    options.config,
    { nickname, origin: payload.origin, userAgent: payload.userAgent, lastUsedAt: payload.lastUsedAt },
    webauthnMap,
  );

  if (recordBuild.debug.typeConflicts.length > 0) {
    throw new PersistError('Type conflicts detected while building credential record', 'PERSIST_SCHEMA_MISMATCH', {
      missing_required_fields: Array.from(new Set(recordBuild.debug.missingRequired)),
      dropped_unknown_fields: recordBuild.debug.droppedUnknown,
      type_conflicts: recordBuild.debug.typeConflicts,
      suggestion: 'run tools/provision_webauthn_storage_directus.py',
    });
  }
  if (recordBuild.debug.missingRequired.length > 0) {
    throw new PersistError(
      `Missing required fields: ${Array.from(new Set(recordBuild.debug.missingRequired)).join(', ')}`,
      'PERSIST_SCHEMA_MISMATCH',
      {
        missing_required_fields: Array.from(new Set(recordBuild.debug.missingRequired)),
        dropped_unknown_fields: recordBuild.debug.droppedUnknown,
        type_conflicts: recordBuild.debug.typeConflicts,
        suggestion: 'run tools/provision_webauthn_storage_directus.py',
      },
    );
  }

  const writableFields = new Set(fieldMap.keys());
  const record = filterRecordToKnownFields(recordBuild.record, writableFields);

  try {
    const created = await items.createOne(record);
    const pk = typeof created === 'object' ? (created as any)?.id ?? (created as any)?.pk ?? null : created ?? null;
    const stored = { ...record, ...(typeof created === 'object' ? created : { id: pk }) } as StoredCredential;

    if (options.debugPersist) {
      const verifyField = recordBuild.credentialIdField ?? 'credential_id';
      const verifyResult = await items.readByQuery({
        filter: { [verifyField]: { _eq: payload.credentialIdB64u } },
        limit: 1,
      });
      const persisted = (verifyResult?.data ?? verifyResult ?? [])[0];
      if (!persisted) {
        throw new PersistError('write_verify_failed', 'write_verify_failed');
      }
    }

    return { record: stored, debug: recordBuild.debug, credentialIdField: recordBuild.credentialIdField };
  } catch (persistError: any) {
    invalidateCollectionFieldMap(collection);
    const isUnique = isUniqueConstraintError(persistError);
    if (!isUnique) {
      const fallbackInsert = await insertCredentialWithKnex(context, collection, record);
      if (fallbackInsert) {
        const stored = { ...record, ...fallbackInsert } as StoredCredential;
        return { record: stored, debug: recordBuild.debug, credentialIdField: recordBuild.credentialIdField };
      }
      if (isForbiddenError(persistError)) {
        throw new PersistError('Write forbidden for WebAuthn credentials', 'PERSIST_FORBIDDEN');
      }
      const unknownFieldMatch = /column "?(?<field>[^"]+)"? does not exist/i.exec(persistError?.message ?? '');
      if (unknownFieldMatch?.groups?.field) {
        throw new PersistError('Unknown field in credential payload', 'PERSIST_SCHEMA_MISMATCH', {
          unknown_field: unknownFieldMatch.groups.field,
        });
      }
      const typeMismatch = /invalid input syntax for type\s+"?(?<expected>[^" ]+)"?/i.exec(persistError?.message ?? '');
      if (typeMismatch?.groups?.expected) {
        throw new PersistError('Invalid value type for credential field', 'PERSIST_SCHEMA_MISMATCH', {
          expected_type: typeMismatch.groups.expected,
          message: persistError?.message ?? null,
        });
      }
      const reason =
        typeof persistError?.message === 'string' && persistError.message.trim()
          ? persistError.message.trim()
          : 'Persist failed';
      throw new PersistError('Database write failed', 'PERSIST_DB_ERROR', {
        message: reason,
        code: (persistError as any)?.code ?? (persistError as any)?.status ?? null,
      });
    }

    const fieldMapResult = await getWebauthnCredentialsFieldMap(context, collection);
    const fieldMap = fieldMapResult.fieldMap;
    const credentialIdField = fieldMap.credentialIdField;
    const existingResult = await items.readByQuery({
      filter: { [credentialIdField]: { _eq: payload.credentialIdB64u } },
      limit: 1,
      fields: buildCredentialFieldList(fieldMap),
    });
    const existingRaw = (existingResult?.data ?? existingResult ?? [])[0];
    const existing = projectCredential(existingRaw, fieldMap);
    if (!existing) throw new PersistError('Unique constraint violation but record not found', 'PERSIST_SCHEMA_MISMATCH');
    if (`${existing.user}` !== `${userId}`) {
      throw new RegistrationInfoError('credential already registered to another user');
    }

    const updateBase: Record<string, any> = {};
    if (fieldMap.signCountField) {
      updateBase[fieldMap.signCountField] = Number.isFinite(payload.counter) ? payload.counter : 0;
    }
    if (fieldMap.transportsField) {
      updateBase[fieldMap.transportsField] = Array.isArray(payload.transports)
        ? payload.transports
        : payload.transports === null
          ? null
          : [];
    }
    if (fieldMap.lastUsedAtField) {
      updateBase[fieldMap.lastUsedAtField] = payload.lastUsedAt ?? new Date().toISOString();
    }

    if (fieldMap.publicKeyField && (!existing.public_key || existing.public_key !== payload.publicKeyB64u)) {
      updateBase[fieldMap.publicKeyField] = payload.publicKeyB64u;
    }
    if (writableFields.has('rp_id')) {
      updateBase.rp_id = payload.rpId ?? null;
    }
    if (writableFields.has('user_agent')) {
      updateBase.user_agent = payload.userAgent ?? existing.user_agent ?? null;
    }
    if (writableFields.has('origin')) {
      updateBase.origin = payload.origin ?? existing.origin ?? null;
    }
    if (writableFields.has('aaguid')) {
      updateBase.aaguid = payload.aaguid ?? existing.aaguid ?? null;
    }
    if (writableFields.has('device_type')) {
      updateBase.device_type = payload.deviceType ?? existing.device_type ?? null;
    }
    if (writableFields.has('backed_up')) {
      updateBase.backed_up = payload.backedUp ?? existing.backed_up ?? null;
    }

    const updateData = filterRecordToKnownFields(updateBase, writableFields);
    const pk = (existing as any)?.id ?? (existing as any)?.pk ?? null;
    let updated = false;
    if (pk) {
      await items.updateOne(pk, updateData);
      updated = true;
    } else {
      updated = await updateItemsByQueryWithFallback(items, {
        filter: { [credentialIdField]: { _eq: payload.credentialIdB64u } },
        limit: 1,
        data: updateData,
      });
    }
    if (!updated) {
      throw new PersistError('WebAuthn credential update unavailable', 'PERSIST_UPDATE_METHOD_MISSING');
    }

    if (options.debugPersist) {
      const verifyResult = await items.readByQuery({
        filter: { [credentialIdField]: { _eq: payload.credentialIdB64u } },
        limit: 1,
      });
      const persisted = (verifyResult?.data ?? verifyResult ?? [])[0];
      if (!persisted) {
        throw new PersistError('write_verify_failed', 'write_verify_failed');
      }
    }

    return {
      record: { ...existing, ...updateData, credential_id: payload.credentialIdB64u } as StoredCredential,
      debug: recordBuild.debug,
      credentialIdField,
    };
  }
}

export function registerWebauthnRoutes(
  router: Router,
  deps: {
    context: ApiExtensionContext;
    baseEnv: Record<string, string | undefined>;
    logger?: any;
    exceptions?: Partial<WebauthnExceptions>;
    overrides?: WebAuthnServerOverrides;
  },
): void {
  const normalizedExceptions = resolveExceptions(deps.exceptions);
  const handlers = createRouteHandlers(deps.context, deps.baseEnv, deps.logger, normalizedExceptions, deps.overrides);
  deps.logger?.info?.('[WEBAUTHN] endpoint mounted', {
    extension_path: EXTENSION_DIR,
    mount_path: '/webauthn',
  });

  router.get('/', handlers.health);
  router.get('/health', handlers.health);
  router.get('/diag/build', handlers.diagBuild);
  router.get('/diag', handlers.diagnostics);
  router.get('/diag/schema', handlers.schemaDiagnostics);
  router.get('/diag/match', handlers.matchDiagnostics);
  router.post('/registration/options', handlers.registrationOptions);
  router.post('/registration/verify', handlers.registrationVerify);
  router.post('/registration/start', handlers.registrationOptions);
  router.post('/registration/finish', handlers.registrationVerify);
  router.post('/register/start', handlers.registrationOptions);
  router.post('/register/finish', handlers.registrationVerify);
  router.post('/authentication/options', handlers.authenticationOptions);
  router.post('/authentication/verify', handlers.authenticationVerify);
  router.post('/login/start', handlers.authenticationOptions);
  router.post('/login/finish', handlers.authenticationVerify);
  router.post('/login/verify', handlers.authenticationVerify);
  router.post('/drytest/options', handlers.drytestOptions);
  router.post('/drytest/verify', handlers.drytestVerify);
  router.post('/otp/options', handlers.drytestOptions);
  router.post('/otp/verify', handlers.drytestVerify);
  router.get('/credentials', handlers.listCredentials);
  router.get('/credentials/', handlers.listCredentials);
  router.delete('/credentials/:id', handlers.deleteCredential);
}

export const __testables = {
  toAllowCredentials,
  toSafeCredentialId,
  credentialIdsMatch,
  normalizeCredentialIdString,
  parseStoredChallenge,
};
export { normalizeToBuffer, toBase64Url } from './utils.js';
export type { WebAuthnConfig };

function createRouteHandlers(
  context: ApiExtensionContext,
  baseEnv: Record<string, string | undefined>,
  logger: any,
  exceptions: NormalizedExceptions,
  overrides?: WebAuthnServerOverrides,
) {
  const { InvalidCredentialsError, InvalidPayloadError } = exceptions;
  const normalizedBaseEnv = { ...process.env, ...baseEnv } as Record<string, string | undefined>;
  const nodeEnvDev = `${process.env.NODE_ENV ?? ''}`.trim().toLowerCase() === 'development';
  const verboseLogging = isDevEnv(normalizedBaseEnv) || nodeEnvDev;
  const debugPersist = `${normalizedBaseEnv['WEBAUTHN_DEBUG'] ?? ''}`.trim().toLowerCase() === 'true';
  const persistMetaEnabled = debugPersist || verboseLogging;
  const defaultChallengeTtlMs = parseDurationToMs(
    normalizedBaseEnv['WEBAUTHN_TIMEOUT_MS'],
    60_000,
  );
  const provisionCommand = buildProvisionCommand(normalizedBaseEnv);
  assertNoDriftConfig(normalizedBaseEnv, logger);
  const ensureStorage = async (req: Request | null, reasonTag: string) => {
    const debugId = req ? ensureDebugId(req) : randomUUID();
    try {
      return await ensureWebauthnStorage(context, normalizedBaseEnv, logger);
    } catch (error: any) {
      if (error && typeof error === 'object') {
        (error as any).reasonTag = reasonTag;
        (error as any).debugId = debugId;
      }
      throw error;
    }
  };

  let AuthService = (context as any).services?.AuthenticationService ?? null;
  const serverFns = {
    generateAuthenticationOptions: overrides?.generateAuthenticationOptions ?? generateAuthenticationOptions,
    generateRegistrationOptions: overrides?.generateRegistrationOptions ?? generateRegistrationOptions,
    verifyAuthenticationResponse: overrides?.verifyAuthenticationResponse ?? verifyAuthenticationResponse,
    verifyRegistrationResponse: overrides?.verifyRegistrationResponse ?? verifyRegistrationResponse,
  };

  const ensureRequestId = (req: Request) => {
    const existing = (req as any).webauthnRequestId;
    if (existing && typeof existing === 'string') return existing;
    const incoming = req.get('x-request-id');
    const normalized = typeof incoming === 'string' && incoming.trim() ? incoming.trim() : null;
    const id = normalized ?? randomUUID();
    (req as any).webauthnRequestId = id;
    return id;
  };

  const ensureDebugId = (req: Request) => {
    const existing = (req as any).webauthnDebugId;
    if (existing && typeof existing === 'string') return existing;
    const id = randomUUID();
    (req as any).webauthnDebugId = id;
    return id;
  };

  const logDev = (level: 'info' | 'warn' | 'debug', message: string, meta?: any) => {
    if (!verboseLogging) return;
    const safeMeta = meta && typeof meta === 'object' ? { ...meta } : meta;
    if (safeMeta && typeof safeMeta === 'object' && 'credential' in safeMeta) {
      (safeMeta as any).credential = redactCredentialPayload((safeMeta as any).credential);
    }
    const debugId =
      (safeMeta as any)?.debug_id ?? (safeMeta as any)?.debugId ?? (safeMeta && typeof safeMeta === 'object' && 'debugId' in safeMeta
        ? (safeMeta as any).debugId
        : null);
    const taggedMessage = debugId ? `[WEBAUTHN][${debugId}] ${message}` : message;
    logger?.[level]?.(taggedMessage, safeMeta);
  };

  const pickCredentialFields = (registrationInfo: any, credentialFromClient: any) => {
    const { InvalidCredentialsError } = exceptions;
    const credentialContainer = registrationInfo?.credential ?? null;

    const idRaw =
      credentialContainer?.id ??
      registrationInfo?.credentialID ??
      registrationInfo?.credentialId ??
      credentialFromClient?.id ??
      credentialFromClient?.rawId;

    if (idRaw === undefined || idRaw === null) {
      throw new InvalidCredentialsError('credential id missing');
    }

    let credentialIdB64u: string | null = null;
    if (typeof idRaw === 'string') {
      const trimmed = idRaw.trim();
      if (!isBase64UrlString(trimmed)) {
        throw new InvalidCredentialsError('credential id missing');
      }
      credentialIdB64u = trimmed;
    } else {
      const idBuffer = normalizeToBufferLoose(idRaw);
      if (idBuffer) {
        credentialIdB64u = isoBase64URL.fromBuffer(toArrayBufferView(idBuffer));
      }
      if (!credentialIdB64u || !isBase64UrlString(credentialIdB64u)) {
        throw new InvalidCredentialsError('credential id missing');
      }
    }

    const pubRaw = credentialContainer?.publicKey ?? registrationInfo?.credentialPublicKey;
    const pubBuffer = normalizeToBufferLoose(pubRaw);
    if (!pubBuffer) {
      throw new InvalidCredentialsError('credentialPublicKey missing');
    }
    const publicKeyB64u = isoBase64URL.fromBuffer(toArrayBufferView(pubBuffer));

    const counterRaw = credentialContainer?.counter ?? registrationInfo?.counter ?? 0;
    const counter = Number.isFinite(counterRaw) ? Number(counterRaw) : Number(counterRaw ?? 0) || 0;

    const transportsRaw =
      credentialContainer?.transports ??
      registrationInfo?.transports ??
      credentialFromClient?.response?.transports ??
      [];
    const transports = Array.isArray(transportsRaw) ? transportsRaw : [];

    const coseAlgRaw =
      credentialContainer?.coseAlg ??
      credentialContainer?.credentialAlg ??
      registrationInfo?.credentialAlgorithm ??
      registrationInfo?.credentialAlg ??
      registrationInfo?.coseAlg ??
      registrationInfo?.cose_alg ??
      null;
    const coseAlg =
      typeof coseAlgRaw === 'number' && Number.isFinite(coseAlgRaw)
        ? coseAlgRaw
        : typeof coseAlgRaw === 'string' && coseAlgRaw.trim() && Number.isFinite(Number(coseAlgRaw))
          ? Number(coseAlgRaw)
          : null;

    const aaguidRaw = credentialContainer?.aaguid ?? registrationInfo?.aaguid ?? null;
    const deviceTypeRaw =
      credentialContainer?.deviceType ??
      credentialContainer?.credentialDeviceType ??
      registrationInfo?.credentialDeviceType ??
      null;
    const backedUpRaw =
      typeof credentialContainer?.backedUp === 'boolean'
        ? credentialContainer.backedUp
        : typeof credentialContainer?.credentialBackedUp === 'boolean'
          ? credentialContainer.credentialBackedUp
          : typeof registrationInfo?.credentialBackedUp === 'boolean'
            ? registrationInfo.credentialBackedUp
            : null;

    return {
      credentialIdB64u,
      publicKeyB64u,
      counter,
      transports,
      coseAlg,
      aaguid: typeof aaguidRaw === 'string' ? aaguidRaw : null,
      deviceType: typeof deviceTypeRaw === 'string' ? deviceTypeRaw : null,
      backedUp: typeof backedUpRaw === 'boolean' ? backedUpRaw : null,
    } as const;
  };

  const getSessionMode = (rawMode: any): 'json' | 'cookie' | 'session' => {
    if (rawMode === 'cookie' || rawMode === 'json' || rawMode === 'session') return rawMode;
    return 'session';
  };

  const normalizeAssertionPayload = (raw: any) => {
    const payload = expectObject(raw ?? {}, 'authentication payload must be an object');
    const credentialSource = (payload as any).credential ?? payload;
    const credential = expectObject(credentialSource, 'credential response is required');
    const response = expectObject((credential as any).response, 'credential response is required');
    const id = expectString((credential as any).id ?? (credential as any).rawId, 'credential id is required');
    const authData = expectString(
      (response as any).authenticatorData ?? (response as any).authData ?? '',
      'authenticatorData is required',
    );
    const clientData = expectString((response as any).clientDataJSON ?? '', 'clientDataJSON is required');
    const signature = expectString((response as any).signature ?? '', 'signature is required');
    const userHandle = typeof (response as any).userHandle === 'string' ? (response as any).userHandle : null;
    const attemptRaw = (payload as any).attemptId ?? (payload as any).requestId ?? (payload as any).id ?? null;
    const attemptId = typeof attemptRaw === 'string' && attemptRaw.trim() ? attemptRaw.trim() : null;

    return {
      credential: {
        id,
        rawId: id,
        type: 'public-key' as const,
        response: {
          authenticatorData: authData,
          clientDataJSON: clientData,
          signature,
          userHandle,
        },
        clientExtensionResults: (credential as any).clientExtensionResults ?? {},
      },
      attemptId,
    };
  };

  async function issueDirectusSession(
    req: Request,
    res: Response,
    userId: string,
    mode: 'json' | 'cookie' | 'session',
  ) {
    const { ServiceUnavailableError } = exceptions;
    if (!AuthService || typeof AuthService !== 'function') {
      throw new ServiceUnavailableError({ service: 'authentication', reason: 'AuthenticationService unavailable' });
    }

    const rawKnex = (context as any).database ?? (context as any).knex ?? (context as any).databaseClient ?? null;
    const knex =
      typeof rawKnex === 'function'
        ? rawKnex
        : rawKnex && typeof (rawKnex as any).table === 'function'
          ? (table: string) => (rawKnex as any).table(table)
          : null;
    if (!knex) {
      throw new ServiceUnavailableError({ service: 'database', reason: 'Knex client unavailable for session creation' });
    }

    const schema = (await (context as any).getSchema?.()) ?? (context as any).schema;
    const accountability = createDefaultAccountability({
      ip: getIPFromReq(req),
      userAgent: req.get('user-agent')?.substring(0, 1024) ?? null,
      origin: req.get('origin') ?? null,
    });

    const authService = new AuthService({ accountability, schema, knex });
    const refreshSeed = nanoid(64);
    const ttlLabel = mode === 'session' ? 'SESSION_COOKIE_TTL' : 'REFRESH_TOKEN_TTL';
    const expiresInMs = parseDurationToMs(
      normalizedBaseEnv[ttlLabel],
      mode === 'session' ? 60 * 60 * 1000 : 30 * 24 * 60 * 60 * 1000,
    );
    const refreshExpires = new Date(Date.now() + expiresInMs);

    const sessionTable = knex('directus_sessions');
    if (!sessionTable || typeof (sessionTable as any).insert !== 'function') {
      throw new ServiceUnavailableError({ service: 'database', reason: 'Knex session table unavailable' });
    }
    const refreshCookieName = normalizedBaseEnv['REFRESH_TOKEN_COOKIE_NAME'] || 'directus_refresh_token';
    const sessionCookieName = normalizedBaseEnv['SESSION_COOKIE_NAME'] || 'directus_session_token';
    await sessionTable.insert({
      token: refreshSeed,
      user: userId,
      expires: refreshExpires,
      ip: accountability.ip,
      user_agent: accountability.userAgent,
      origin: accountability.origin,
    });

    const diagnosticsAllowed = diagnosticsAllowedForRequest(req, normalizedBaseEnv);
    let tokens;
    try {
      const protoMethods = Object.getOwnPropertyNames(Object.getPrototypeOf(authService));
      if (typeof (authService as any).refresh !== 'function') {
        const error = new ServiceUnavailableError({
          service: 'authentication',
          reason: 'AUTH_SERVICE_METHOD_MISSING',
        });
        (error as any).methods = protoMethods;
        throw error;
      }
      tokens = await (authService as any).refresh(refreshSeed, { session: mode === 'session' });
    } catch (error) {
      if (diagnosticsAllowed) {
        const debugId = ensureDebugId(req);
        logger?.error?.('[WEBAUTHN] auth refresh failed', {
          route: 'authentication/verify',
          userId,
          requestId: (req as any).webauthnRequestId ?? null,
          debug_id: debugId,
          error_message: error?.message ?? null,
          error_stack: error?.stack ?? null,
        });
      }
      if (error instanceof TypeError) {
        const protoMethods = Object.getOwnPropertyNames(Object.getPrototypeOf(authService));
        const typeError = new ServiceUnavailableError({
          service: 'authentication',
          reason: 'AUTH_SERVICE_REFRESH_TYPEERROR',
        });
        (typeError as any).methods = protoMethods;
        throw typeError;
      }
      await sessionTable.where({ token: refreshSeed }).del().catch(() => undefined);
      throw error;
    }

    if (!tokens || typeof tokens !== 'object' || (!tokens.accessToken && !tokens.refreshToken)) {
      const error = new ServiceUnavailableError({
        service: 'authentication',
        reason: 'AUTH_SERVICE_TOKENS_MISSING',
      });
      if (diagnosticsAllowed) {
        (error as any).tokens = tokens ?? null;
      }
      await sessionTable.where({ token: refreshSeed }).del().catch(() => undefined);
      throw error;
    }

    if (mode === 'cookie' || mode === 'session') {
      if (tokens.refreshToken) {
        res.cookie(refreshCookieName, tokens.refreshToken, cookieOptionsFromEnv(normalizedBaseEnv, 'refresh'));
      }
      if (mode === 'session' && tokens.accessToken) {
        res.cookie(sessionCookieName, tokens.accessToken, cookieOptionsFromEnv(normalizedBaseEnv, 'session'));
      }
    }

    logDev('info', '[webauthn][auth/session] issued tokens', {
      requestId: (req as any).webauthnRequestId ?? null,
      debug_id: (req as any).webauthnDebugId ?? null,
      userId,
      mode,
      hasAccessToken: Boolean(tokens?.accessToken),
      hasRefreshToken: Boolean(tokens?.refreshToken),
      setSessionCookie: mode === 'session',
      setRefreshCookie: mode === 'cookie',
      sessionCookieName: mode === 'session' ? sessionCookieName : null,
      refreshCookieName: mode === 'cookie' ? refreshCookieName : null,
    });

    return tokens;
  }
  async function registrationOptions(req: Request, res: Response, next: NextFunction) {
    let lastConfig: WebAuthnConfig | null = null;
    let hostname: string | null = null;
    let debugId: string | null = null;
    const diagnosticsAllowed = diagnosticsAllowedForRequest(req, normalizedBaseEnv);
    try {
      const requestId = ensureRequestId(req);
      debugId = ensureDebugId(req);
      const meta = { requestId };
      hostname = requestHostname(req);
      const storageStatus = await ensureStorage(req, 'registration_options');
      const { userId: actingUserId } = ensureLoggedIn(req, exceptions);
      const body = expectObject(req.body ?? {}, 'registration/options payload must be an object');
      const { userId: bodyUserId, userIdOverride, userId } = body as any;
      const targetUserId = `${bodyUserId ?? userIdOverride ?? userId ?? actingUserId}`;
      const accountability = (req as any).accountability ?? { user: targetUserId };
      const { config } = resolveConfigForRequest(req, normalizedBaseEnv, logger);
      lastConfig = config;
      const credentialsCollection = storageStatus.collections.credentials;
      const challengeCollection = storageStatus.collections.challenges;
      await cleanupChallenges(context, challengeCollection, exceptions, logger).catch(() => undefined);
      const user = await loadUser(context, targetUserId, accountability, exceptions);
      const credentials = await listCredentials(context, credentialsCollection, targetUserId, accountability, exceptions);
      const allow = toAllowCredentials(credentials);
      const excludeCredentials = allow as any;
      const userIdBytes = toArrayBufferView(Buffer.from(`${user.id}`));
      logger?.info?.(
        `[webauthn][registration/options] user=${targetUserId} existing=${allow.length} rpId=${config.rpId} origins=${config.origins.join(',')}`,
      );

      const attemptId = randomUUID();
      const issuedAt = new Date().toISOString();

      const options = await serverFns.generateRegistrationOptions({
        rpID: config.rpId,
        rpName: config.rpName,
        userID: userIdBytes,
        userName: user.email ?? `${user.id}`,
        userDisplayName: user.email ?? `${user.id}`,
        attestationType: 'none',
        excludeCredentials,
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: config.userVerification,
        },
        timeout: config.timeoutMs,
      });

      await saveChallenge(
        context,
        accountability,
        challengeCollection,
        {
          attemptId,
          userId: targetUserId,
          type: 'registration',
          flow: 'registration',
          challenge: options.challenge,
          rpId: config.rpId,
          origins: config.origins,
          allowedCredentialIds: allow.map((entry) => toBase64Url(entry.id)!).filter(Boolean),
          ttlMs: defaultChallengeTtlMs,
        },
        exceptions,
      );

      const publicKey = {
        ...options,
        rpId: config.rpId,
        rp: { id: config.rpId, name: config.rpName, ...(options as any).rp },
      } as typeof options & { rpId: string };

      respondOk(
        res,
        {
          publicKey,
          attemptId,
          context: {
            flow: 'registration',
            user_id: targetUserId,
            request_id: attemptId,
            issued_at: issuedAt,
          },
        },
        meta,
      );
    } catch (error) {
      handleError(error, res, next, logger, exceptions, verboseLogging, {
        requestId: (req as any).webauthnRequestId,
        route: 'registration/options',
        rpId: lastConfig?.rpId,
        hostname,
        diagnosticsAllowed,
        env: normalizedBaseEnv,
        debugId,
      });
    }
  }

  async function registrationVerify(req: Request, res: Response, next: NextFunction) {
    let lastConfig: WebAuthnConfig | null = null;
    let hostname: string | null = null;
    let debugId: string | null = null;
    const diagnosticsAllowed = diagnosticsAllowedForRequest(req, normalizedBaseEnv);
    try {
      const requestId = ensureRequestId(req);
      debugId = ensureDebugId(req);
      const meta = { requestId };
      hostname = requestHostname(req);
      const payload = req.body;
      if (!payload || typeof payload !== 'object' || Array.isArray(payload) || typeof (payload as any).credential !== 'object') {
        return respondError(
          res,
          400,
          'invalid_webauthn_response',
          'registration/verify requires { credential: {...} }',
          { stage: 'validate' },
          diagnosticsAllowed ? 'registration/verify requires { credential: {...} }' : null,
          { ...meta, debug_id: debugId },
        );
      }
      const storageStatus = await ensureStorage(req, 'registration_verify');
      const { userId } = ensureLoggedIn(req, exceptions);
      const body = expectObject(payload ?? {}, 'registration/verify payload must be an object');
      const credential = expectObject((body as any).credential, 'credential response is required');
      const credentialName = typeof (body as any).credentialName === 'string' ? (body as any).credentialName : null;
      const accountability = (req as any).accountability ?? { user: userId };
      const { config } = resolveConfigForRequest(req, normalizedBaseEnv, logger);
      lastConfig = config;
      const credentialsCollection = storageStatus.collections.credentials;
      const challengeCollection = storageStatus.collections.challenges;
      const challenge = await consumeChallenge(
        context,
        accountability,
        userId,
        'registration',
        challengeCollection,
        exceptions,
        null,
        'registration',
      );
      if (!challenge?.parsed) {
        return respondError(
          res,
          400,
          'invalid_webauthn_response',
          'WebAuthn challenge is missing or invalid',
          { stage: 'challenge', requestId },
          diagnosticsAllowed ? 'Challenge missing or unparsable in storage' : null,
          { ...meta, debug_id: debugId },
        );
      }
      const parsedChallenge = expectObject(challenge.parsed ?? null, 'registration challenge is invalid');
      const parsedOrigins = Array.isArray((parsedChallenge as any).origins)
        ? (parsedChallenge as any).origins.filter((origin: any) => typeof origin === 'string' && origin.trim())
        : [];
      const parsedRpId =
        typeof (parsedChallenge as any).rpId === 'string' ? (parsedChallenge as any).rpId.trim() : '';
      if (!parsedRpId || parsedOrigins.length === 0) {
        return respondError(
          res,
          400,
          'invalid_webauthn_response',
          'WebAuthn challenge metadata missing',
          { stage: 'challenge', requestId },
          diagnosticsAllowed ? 'Challenge rpId/origins missing in storage' : null,
          { ...meta, debug_id: debugId },
        );
      }
      const expectedOrigins = config.origins;
      const expectedChallenge = String(
        (parsedChallenge as any).challenge ?? (parsedChallenge as any).publicKey?.challenge ?? '',
      );

      if (!expectedChallenge) {
        return respondError(
          res,
          400,
          'invalid_webauthn_response',
          'WebAuthn challenge missing in storage',
          { stage: 'challenge', requestId },
          diagnosticsAllowed ? 'Challenge missing or unparsable in storage' : null,
          { ...meta, debug_id: debugId },
        );
      }

      const verification = await serverFns.verifyRegistrationResponse({
        response: credential,
        expectedChallenge,
        expectedOrigin: expectedOrigins,
        expectedRPID: config.rpId,
        requireUserVerification: config.userVerification === 'required',
      });

      logger?.info?.(
        `[WEBAUTHN][${debugId}] verify registration request=${requestId} verified=${verification.verified} challenge_len=${expectedChallenge.length}`,
        { route: 'registration/verify', rpId: config.rpId },
      );

      if (!verification.verified) {
        throw new InvalidCredentialsError('attestation could not be verified');
      }
      if (!verification.registrationInfo) {
        throw new RegistrationInfoError('registrationInfo missing from verification response');
      }

      const extracted = pickCredentialFields(verification.registrationInfo, credential);
      const credentialPreview = extracted.credentialIdB64u.slice(0, 10) || 'unknown';
      logger?.info?.(
        `[WEBAUTHN][${debugId}] verify.ok credential_id_prefix=${credentialPreview}`,
        { route: 'registration/verify', requestId, rpId: config.rpId },
      );
      const persistMeta: Record<string, any> = { attempted: true, credential_id_prefix: credentialPreview };
      const userAgent = req.get('user-agent')?.slice(0, 1024) ?? null;
      const originHeader = req.get('origin') ?? null;
      const persistPayload = {
        ...extracted,
        userAgent,
        origin: originHeader,
        rpId: config.rpId ?? null,
        lastUsedAt: new Date().toISOString(),
      };

      logger?.info?.(
        `[WEBAUTHN][${debugId}] persist.begin credential_id_prefix=${credentialPreview} rpId=${config.rpId} origin=${originHeader ?? 'n/a'}`,
        { route: 'registration/verify', requestId, rpId: config.rpId, origin: originHeader },
      );

      if (debugPersist) {
        const pubkeyLen = extracted.publicKeyB64u?.length ?? 0;
        logger?.info?.(`[WEBAUTHN][${debugId}] credential_id_prefix = ${credentialPreview}`, {
          route: 'registration/verify',
        });
        logger?.info?.(`[WEBAUTHN][${debugId}] pubkey_len = ${pubkeyLen}`, {
          route: 'registration/verify',
        });
      }
      let record: any;
      let persistDebug: CredentialRecordDebug | null = null;
      try {
        const result = await saveCredential(
          context,
          credentialsCollection,
          userId,
          persistPayload,
          credentialName,
          exceptions,
          { debugPersist, config },
        );
        record = result.record;
        persistDebug = result.debug;
        if (persistDebug) {
          persistMeta.persist_fields = persistDebug.includedFields;
          if (persistDebug.droppedUnknown.length > 0) {
            persistMeta.dropped_unknown_fields = persistDebug.droppedUnknown;
          }
          if (persistDebug.typeConflicts.length > 0) {
            persistMeta.type_conflicts = persistDebug.typeConflicts;
          }
          if (persistDebug.missingRequired.length > 0) {
            persistMeta.missing_required_fields = persistDebug.missingRequired;
          }
        }
        const rowId = (record as any)?.id ?? (record as any)?.pk ?? null;
        logger?.info?.(
          `[WEBAUTHN][${debugId}] persist.ok credential_id=${credentialPreview} row=${rowId ?? 'unknown'}`,
          { route: 'registration/verify', requestId, rpId: config.rpId, origin: originHeader },
        );
        persistMeta.ok = true;
        persistMeta.row = rowId ?? null;
      } catch (persistError: any) {
        if (persistError instanceof RegistrationInfoError) throw persistError;
        const reasonRaw =
          (persistError as any)?.reason ??
          (typeof persistError?.message === 'string' && persistError.message.trim() ? persistError.message.trim() : null) ??
          (persistError as any)?.code ??
          persistError?.name ??
          'persist_failed';
        const reason = typeof reasonRaw === 'string' && reasonRaw ? String(reasonRaw).slice(0, 120) : 'persist_failed';
        persistMeta.ok = false;
        persistMeta.reason = reason;
        logger?.error?.(
          `[WEBAUTHN][${debugId}] persist.fail ${persistError?.name ?? 'Error'}:${persistError?.message ?? 'unknown'}`,
          {
            route: 'registration/verify',
            requestId,
            rpId: config.rpId,
            origin: originHeader,
            error: persistError?.stack ?? persistError,
          },
        );
        if (persistError?.details) {
          persistMeta.details = persistError.details;
        }
        const persistDetails = persistMetaEnabled
          ? { stage: 'persist', reason, persist: persistMeta }
          : { stage: 'persist', reason, details: persistError?.details ?? persistMeta.details ?? null };
        return respondError(
          res,
          500,
          'webauthn_persist_failed',
          'Credential persistence failed',
          persistDetails,
          diagnosticsAllowed ? persistError?.message ?? reason : null,
          { ...meta, debug_id: debugId, ...(persistMetaEnabled ? { persist: persistMeta } : {}) },
        );
      }

      await deleteChallengeById(
        context,
        SERVICE_ACCOUNTABILITY,
        challengeCollection,
        challenge.row.challenge_id ?? challenge.row.id ?? null,
        exceptions,
        logger,
      );

      const responseMeta = persistMetaEnabled ? { ...meta, persist: persistMeta } : meta;
      respondOk(res, { data: { credentialId: record.credential_id, userId } }, responseMeta);
    } catch (error) {
      handleError(error, res, next, logger, exceptions, verboseLogging, {
        requestId: (req as any).webauthnRequestId,
        route: 'registration/verify',
        rpId: lastConfig?.rpId,
        hostname,
        diagnosticsAllowed,
        env: normalizedBaseEnv,
        debugId,
      });
    }
  }

  async function authenticationOptions(req: Request, res: Response, next: NextFunction) {
    let lastConfig: WebAuthnConfig | null = null;
    let hostname: string | null = null;
    let debugId: string | null = null;
    const diagnosticsAllowed = diagnosticsAllowedForRequest(req, normalizedBaseEnv);
    try {
      const requestId = ensureRequestId(req);
      debugId = ensureDebugId(req);
      const meta = { requestId };
      hostname = requestHostname(req);
      const storageStatus = await ensureStorage(req, 'authentication_options');
      const accountability = (req as any).accountability ?? null;
      const body = expectObject(req.body ?? {}, 'authentication/options payload must be an object');
      const requestedFlow = typeof (body as any).mode === 'string' ? (body as any).mode : 'login';
      const flow: 'auth' | 'drytest' = requestedFlow === 'drytest' ? 'drytest' : 'auth';
      const verificationOverride = typeof (body as any).userVerification === 'string' ? (body as any).userVerification : null;
      const usernameInput =
        typeof (body as any).username === 'string'
          ? (body as any).username
          : typeof (body as any).email === 'string'
            ? (body as any).email
            : typeof (body as any).identifier === 'string'
              ? (body as any).identifier
              : null;
      const username = usernameInput ? usernameInput.trim() : null;
      let targetUserId = (accountability as any)?.user ? `${(accountability as any).user}` : null;
      const credentialsAccountability: any = { admin: true };

      if (!targetUserId && username) {
        const candidate = await findUserByEmail(context, username, { admin: true }, exceptions);
        if (candidate) {
          targetUserId = `${candidate.id}`;
        } else {
          return respondError(
            res,
            404,
            'webauthn_user_not_found',
            'User not found for WebAuthn login.',
            { stage: 'lookup' },
            null,
            { ...meta, debug_id: debugId },
          );
        }
      }

      const discoverable = !targetUserId;

      const { config } = resolveConfigForRequest(req, normalizedBaseEnv, logger);
      lastConfig = config;
      const rpId = config.rpId;
      const credentialsCollection = storageStatus.collections.credentials;
      const challengeCollection = storageStatus.collections.challenges;
      await cleanupChallenges(context, challengeCollection, exceptions, logger).catch(() => undefined);
      const userVerification =
        verificationOverride === 'required' || verificationOverride === 'discouraged'
          ? verificationOverride
          : config.userVerification;
      const credentials = targetUserId
        ? await listCredentials(
            context,
            credentialsCollection,
            targetUserId,
            credentialsAccountability,
            exceptions,
          )
        : [];
      const allowCredentials = discoverable ? undefined : (toAllowCredentials(credentials) as any);
      const attemptId = randomUUID();
      const issuedAt = new Date().toISOString();
      const options = await serverFns.generateAuthenticationOptions({
        rpID: rpId,
        allowCredentials,
        userVerification,
        timeout: config.timeoutMs,
      });

      await saveChallenge(
        context,
        credentialsAccountability,
        challengeCollection,
        {
          userId: targetUserId,
          type: 'authentication',
          flow,
          challenge: options.challenge,
          rpId,
          origins: config.origins,
          allowedCredentialIds: (allowCredentials ?? [])
            .map((entry) => toBase64Url(entry.id))
            .filter((v): v is string => typeof v === 'string'),
          ttlMs: defaultChallengeTtlMs,
          attemptId,
        },
        exceptions,
      );

      logDev('info', `[webauthn][authentication/options][${flow}]`, {
        requestId,
        userId: targetUserId,
        attemptId,
        allowCredentials: allowCredentials?.length ?? 0,
        rpId,
        debug_id: debugId,
      });

      respondOk(
        res,
        {
          publicKey: {
            ...options,
            rpId,
            userVerification,
          },
          attemptId,
          context: {
            flow,
            user_id: targetUserId,
            request_id: attemptId,
            issued_at: issuedAt,
          },
        },
        meta,
      );
    } catch (error) {
      handleError(error, res, next, logger, exceptions, verboseLogging, {
        requestId: (req as any).webauthnRequestId,
        route: 'authentication/options',
        rpId: lastConfig?.rpId,
        hostname: requestHostname(req),
        diagnosticsAllowed,
        env: normalizedBaseEnv,
        debugId,
      });
    }
  }

  async function authenticationVerify(req: Request, res: Response, next: NextFunction) {
    let lastConfig: WebAuthnConfig | null = null;
    let hostname: string | null = null;
    let debugId: string | null = null;
    const diagnosticsAllowed = diagnosticsAllowedForRequest(req, normalizedBaseEnv);
    try {
      const requestId = ensureRequestId(req);
      debugId = ensureDebugId(req);
      const meta = { requestId };
      hostname = requestHostname(req);
      const storageStatus = await ensureStorage(req, 'authentication_verify');
      const { credential, attemptId } = normalizeAssertionPayload(req.body);
      const mode = getSessionMode((req.body as any)?.mode);
      const accountability = (req as any).accountability ?? null;
      const hasSessionUser = Boolean((accountability as any)?.user);
      if (!attemptId && !hasSessionUser) {
        throw new InvalidPayloadError({ reason: 'attemptId is required for discoverable credentials' });
      }
      const { config } = resolveConfigForRequest(req, normalizedBaseEnv, logger);
      lastConfig = config;
      const credentialsCollection = storageStatus.collections.credentials;
      const challengeCollection = storageStatus.collections.challenges;
      const fieldMapResult = await getWebauthnCredentialsFieldMap(context, credentialsCollection);
      const fieldMap = fieldMapResult.fieldMap;
      let userId = (accountability as any)?.user ? `${(accountability as any).user}` : null;
      const presentedId = normalizeCredentialIdString(credential?.id ?? credential?.rawId);
      if (!presentedId) {
        throw new InvalidPayloadError({ reason: 'credential id format is invalid' });
      }
      let credentialsAccountability: any = { admin: true };
      let matching = null as StoredCredential | null;
      let storedCredentials: StoredCredential[] = [];

      if (userId) {
        storedCredentials = await listCredentials(
          context,
          credentialsCollection,
          userId,
          credentialsAccountability,
          exceptions,
          fieldMapResult,
        );
        matching = storedCredentials.find((entry) => credentialIdsMatch(presentedId, entry.credential_id)) ?? null;
      } else {
        matching = await findCredentialById(
          context,
          credentialsCollection,
          { admin: true },
          presentedId,
          exceptions,
          fieldMapResult,
        );
        if (matching) {
          userId = `${matching.user}`;
        }
      }

      if (!userId || !matching) {
        const debugDetails = diagnosticsAllowed
          ? {
              presentedIdPrefix: toCredentialIdPrefix(presentedId),
              resolvedUserId: userId,
              storedCount: storedCredentials.length,
              storedCredentialIdPrefixes: storedCredentials
                .map((entry) => toCredentialIdPrefix(normalizeCredentialIdString(entry?.credential_id)))
                .filter(Boolean),
            }
          : undefined;

        return respondError(
          res,
          401,
          'invalid_webauthn_credentials',
          'Credential not registered for this account',
          {
            stage: 'verify',
            reason: 'NO_MATCHING_CREDENTIAL',
            ...debugDetails,
          },
          null,
          { requestId, debug_id: debugId },
        );
      }

      const userLookupAccountability = hasSessionUser ? accountability : SERVICE_ACCOUNTABILITY;
      const challenge = await consumeChallenge(
        context,
        credentialsAccountability,
        userId,
        'authentication',
        challengeCollection,
        exceptions,
        attemptId,
        'auth',
      );

      if (!challenge || !challenge.parsed) {
        logger?.warn?.(`[WEBAUTHN][${debugId}] authentication challenge missing`, {
          requestId,
          attemptId,
          userId,
          route: 'authentication/verify',
        });
        throw new InvalidPayloadError({ reason: 'authentication challenge is missing or invalid' });
      }
      const parsedChallenge = expectObject(challenge.parsed ?? null, 'authentication challenge is invalid');
      const parsedOrigins = Array.isArray((parsedChallenge as any).origins)
        ? (parsedChallenge as any).origins.filter((origin: any) => typeof origin === 'string' && origin.trim())
        : [];
      const parsedRpId =
        typeof (parsedChallenge as any).rpId === 'string' ? (parsedChallenge as any).rpId.trim() : '';
      if (parsedOrigins.length === 0) {
        logger?.warn?.(`[WEBAUTHN][${debugId}] authentication challenge origins missing`, {
          requestId,
          attemptId,
          userId,
          route: 'authentication/verify',
        });
        throw new InvalidPayloadError({ reason: 'challenge origins are missing or invalid' });
      }
      if (!parsedRpId) {
        logger?.warn?.(`[WEBAUTHN][${debugId}] authentication challenge rpId missing`, {
          requestId,
          attemptId,
          userId,
          route: 'authentication/verify',
        });
        throw new InvalidPayloadError({ reason: 'challenge rpId is missing or invalid' });
      }
      const expectedChallengeRaw = (parsedChallenge as any).challenge;
      const expectedChallenge =
        typeof expectedChallengeRaw === 'string' ? expectedChallengeRaw : `${expectedChallengeRaw ?? ''}`;
      if (!expectedChallenge.trim()) {
        logger?.warn?.(`[WEBAUTHN][${debugId}] authentication challenge empty`, {
          requestId,
          attemptId,
          userId,
          route: 'authentication/verify',
        });
        throw new InvalidPayloadError({ reason: 'challenge is missing or invalid' });
      }
      const parsedAllowedCredentialIds = Array.isArray((parsedChallenge as any).allowedCredentialIds)
        ? (parsedChallenge as any).allowedCredentialIds
        : [];
      const allowedIds = parsedAllowedCredentialIds.map((id: any) => normalizeCredentialIdString(id)).filter(Boolean);
      if (allowedIds.length > 0 && !allowedIds.some((id: string | null) => credentialIdsMatch(id, presentedId))) {
        throw new InvalidCredentialsError({ reason: 'Credential was not issued an allowCredentials entry for this attempt' });
      }

      const storedCredentialId = normalizeCredentialIdString(matching.credential_id);
      const storedPublicKey = typeof matching.public_key === 'string' ? matching.public_key.trim() : null;
      if (!storedCredentialId || !storedPublicKey) {
        logger?.warn?.(`[WEBAUTHN][${debugId}] stored credential missing fields`, {
          requestId,
          attemptId,
          userId,
          route: 'authentication/verify',
          hasCredentialId: Boolean(storedCredentialId),
          hasPublicKey: Boolean(storedPublicKey),
        });
        throw new InvalidCredentialsError({ reason: 'Stored credential is invalid' });
      }

      let publicKey: Uint8Array<ArrayBuffer>;
      let credentialIdBytes: Uint8Array<ArrayBuffer>;
      try {
        publicKey = toUint8ArrayFromBase64Url(storedPublicKey, 'public_key');
        credentialIdBytes = toUint8ArrayFromBase64Url(storedCredentialId, 'credential_id');
      } catch (error) {
        throw new InvalidCredentialsError({ reason: 'Stored credential is invalid' });
      }

      const expectedOrigins = parsedOrigins;
      const expectedRpId =
        typeof (parsedChallenge as any).rpId === 'string' && (parsedChallenge as any).rpId.trim()
          ? (parsedChallenge as any).rpId
          : null;
      const effectiveRpId = expectedRpId ?? config.rpId ?? null;
      if (!effectiveRpId) {
        return respondError(
          res,
          503,
          'webauthn_not_configured',
          'RP ID is missing for WebAuthn verification',
          { stage: 'verify', reason: 'MISSING_RPID' },
          diagnosticsAllowed ? 'expectedRPID missing' : null,
          { requestId, debug_id: debugId },
        );
      }
      let verification: Awaited<ReturnType<typeof serverFns.verifyAuthenticationResponse>>;
      try {
        verification = await serverFns.verifyAuthenticationResponse({
          response: credential,
          expectedChallenge,
          expectedOrigin: expectedOrigins,
          expectedRPID: effectiveRpId,
          credential: {
            id: storedCredentialId,
            publicKey,
            counter: matching.sign_count ?? 0,
            transports: Array.isArray(matching.transports)
              ? (matching.transports as AuthenticatorTransportFuture[])
              : undefined,
          },
          requireUserVerification: config.userVerification === 'required',
        });
      } catch (error: any) {
        const debugDetails = diagnosticsAllowed
          ? {
              stage: 'verify',
              reason: 'VERIFY_EXCEPTION',
              expectedRPID: expectedRpId ?? config.rpId ?? null,
              expectedOrigins: expectedOrigins.length ? expectedOrigins : config.origins ?? [],
              challenge_prefix: typeof expectedChallenge === 'string' ? toCredentialIdPrefix(expectedChallenge, 8) : null,
              credential_id_prefix: toCredentialIdPrefix(presentedId, 8),
              public_key_decoded: (() => {
                try {
                  toUint8ArrayFromBase64Url(storedPublicKey, 'public_key');
                  return true;
                } catch {
                  return false;
                }
              })(),
              error: error?.message ?? String(error ?? 'error'),
            }
          : { stage: 'verify', reason: 'VERIFY_EXCEPTION' };

        return respondError(
          res,
          401,
          'invalid_webauthn_credentials',
          'Authentication response verification failed',
          debugDetails,
          diagnosticsAllowed ? error?.message ?? null : null,
          { requestId, debug_id: debugId },
        );
      }

      if (!verification) {
        return respondError(
          res,
          503,
          'webauthn_service_unavailable',
          'Authentication verification unavailable',
          { stage: 'verify', reason: 'VERIFY_EMPTY_RESPONSE' },
          diagnosticsAllowed ? 'verifyAuthenticationResponse returned empty response' : null,
          { requestId, debug_id: debugId },
        );
      }

      if (!verification.verified || !verification.authenticationInfo) {
        throw new InvalidCredentialsError({ reason: 'Authentication response could not be verified' });
      }

      const nextCounter = verification.authenticationInfo.newCounter ?? matching.sign_count ?? 0;
      const priorCounter = matching.sign_count ?? 0;
      if (nextCounter < priorCounter) {
        throw new InvalidCredentialsError({ reason: 'Sign count regressed for credential' });
      }

      const items = await createItemsService(
        credentialsCollection,
        context,
        credentialsAccountability,
        exceptions,
      );
      if (!fieldMap.signCountField) {
        throw new WebauthnSchemaMappingError('WebAuthn credential schema incomplete', ['sign_count'], fieldMapResult.availableFields);
      }
      const updateFieldName = fieldMap.signCountField;
      const updateData: Record<string, any> = { [updateFieldName]: nextCounter };
      if (fieldMap.lastUsedAtField) {
        updateData[fieldMap.lastUsedAtField] = new Date().toISOString();
      }
      const updated = await updateItemsByQueryWithFallback(
        items,
        {
          filter: { [fieldMap.credentialIdField]: { _eq: matching.credential_id } },
          limit: 1,
          data: updateData,
        },
        { fallbackId: matching.id ?? null },
      );
      if (!updated) {
        logger?.warn?.('[WEBAUTHN] credential update skipped (missing update method)', {
          requestId,
          debug_id: debugId,
          credential_id: matching.credential_id,
        });
      }

      let user = null as any;
      let userLookupDenied = false;
      try {
        const lookupAccountability = hasSessionUser ? accountability : SERVICE_ACCOUNTABILITY;
        user = await loadUser(context, userId, lookupAccountability, exceptions);
      } catch (error) {
        if (!isForbiddenError(error)) {
          throw error;
        }
        userLookupDenied = true;
        logger?.warn?.(`[WEBAUTHN][${debugId}] user lookup forbidden; continuing`, {
          requestId,
          userId,
          route: 'authentication/verify',
        });
      }
      if (!user || !(user as any).id) {
        user = { id: userId };
      }
      const usedKey = {
        credentialId: matching.credential_id,
        nickname: matching.nickname ?? 'Passkey',
        deviceType: matching.device_type ?? null,
      };

      logDev('info', '[webauthn][authentication/verify] success', {
        userId,
        credentialId: matching.credential_id,
        attemptId,
        requestId,
        debug_id: debugId,
      });

      let tokens;
      try {
        tokens = await issueDirectusSession(req, res, userId, mode);
      } catch (error: any) {
        if (error instanceof TypeError) {
          return respondError(
            res,
            503,
            'webauthn_service_unavailable',
            'Token issuance failed',
            { stage: 'token', reason: 'TOKEN_ISSUANCE_TYPEERROR' },
            diagnosticsAllowed ? error?.message ?? null : null,
            { requestId, debug_id: debugId },
          );
        }
        throw error;
      }
      await deleteChallengeById(
        context,
        SERVICE_ACCOUNTABILITY,
        challengeCollection,
        challenge.row.challenge_id ?? challenge.row.id ?? null,
        exceptions,
        logger,
      );
      respondOk(
        res,
        {
          access_token: tokens?.accessToken ?? null,
          refresh_token: tokens?.refreshToken ?? null,
          expires: tokens?.expires ?? null,
          user: { id: user.id, email: userLookupDenied ? null : user.email ?? null },
          result: {
            credential_id: matching.credential_id,
            label: matching.nickname ?? 'Passkey',
            type: toCredentialType(matching.device_type),
          },
          context: {
            flow: 'auth',
            user_id: userId,
            request_id: attemptId ?? (parsedChallenge as any).attemptId ?? null,
          },
        },
        meta,
      );
    } catch (error) {
      handleError(error, res, next, logger, exceptions, verboseLogging, {
        requestId: (req as any).webauthnRequestId,
        route: 'authentication/verify',
        rpId: lastConfig?.rpId,
        hostname,
        diagnosticsAllowed,
        env: normalizedBaseEnv,
        debugId,
      });
    }
  }

  async function drytestOptions(req: Request, res: Response, next: NextFunction) {
    let lastConfig: WebAuthnConfig | null = null;
    let hostname: string | null = null;
    let debugId: string | null = null;
    const diagnosticsAllowed = diagnosticsAllowedForRequest(req, normalizedBaseEnv);
    try {
      const requestId = ensureRequestId(req);
      debugId = ensureDebugId(req);
      hostname = requestHostname(req);
      const storageStatus = await ensureStorage(req, 'drytest_options');
      const { userId } = ensureLoggedIn(req, exceptions);
      expectObject(req.body ?? {}, 'drytest/options payload must be an object');
      const accountability = (req as any).accountability ?? { user: userId };
      const { config } = resolveConfigForRequest(req, normalizedBaseEnv, logger);
      lastConfig = config;
      const credentialsCollection = storageStatus.collections.credentials;
      const challengeCollection = storageStatus.collections.challenges;
      await cleanupChallenges(context, challengeCollection, exceptions, logger).catch(() => undefined);
      const credentials = await listCredentials(
        context,
        credentialsCollection,
        userId,
        accountability,
        exceptions,
      );
      const allowCredentials = toAllowCredentials(credentials) as any;
      const attemptId = randomUUID();
      const issuedAt = new Date().toISOString();

      const options = await serverFns.generateAuthenticationOptions({
        rpID: config.rpId,
        allowCredentials,
        userVerification: config.userVerification,
        timeout: config.timeoutMs,
      });

      await saveChallenge(
        context,
        accountability,
        challengeCollection,
        {
          userId,
          type: 'authentication',
          flow: 'drytest',
          challenge: options.challenge,
          rpId: config.rpId,
          origins: config.origins,
          allowedCredentialIds: allowCredentials
            .map((entry) => toBase64Url(entry.id))
            .filter((v): v is string => typeof v === 'string'),
          ttlMs: defaultChallengeTtlMs,
          attemptId,
        },
        exceptions,
      );

      logDev('info', '[webauthn][drytest/options]', {
        userId,
        attemptId,
        allowCredentials: allowCredentials.length,
        requestId,
        debug_id: debugId,
      });
      respondOk(
        res,
        {
          publicKey: {
            ...options,
            rpId: config.rpId,
          },
          context: {
            flow: 'drytest',
            user_id: userId,
            request_id: attemptId,
            issued_at: issuedAt,
          },
        },
        { requestId },
      );
    } catch (error) {
      handleError(error, res, next, logger, exceptions, verboseLogging, {
        requestId: (req as any).webauthnRequestId,
        route: 'drytest/options',
        rpId: lastConfig?.rpId,
        hostname,
        diagnosticsAllowed,
        env: normalizedBaseEnv,
        debugId,
      });
    }
  }

  async function drytestVerify(req: Request, res: Response, next: NextFunction) {
    let lastConfig: WebAuthnConfig | null = null;
    let hostname: string | null = null;
    let debugId: string | null = null;
    const diagnosticsAllowed = diagnosticsAllowedForRequest(req, normalizedBaseEnv);
    try {
      const requestId = ensureRequestId(req);
      debugId = ensureDebugId(req);
      hostname = requestHostname(req);
      const { userId } = ensureLoggedIn(req, exceptions);
      const { credential, attemptId } = normalizeAssertionPayload(req.body);
      const accountability = (req as any).accountability ?? { user: userId };
      const storageStatus = await ensureStorage(req, 'drytest_verify');
      const { config } = resolveConfigForRequest(req, normalizedBaseEnv, logger);
      lastConfig = config;
      const credentialsCollection = storageStatus.collections.credentials;
      const challengeCollection = storageStatus.collections.challenges;
      const fieldMapResult = await getWebauthnCredentialsFieldMap(context, credentialsCollection);
      const fieldMap = fieldMapResult.fieldMap;
      const credentialId = credential?.id ?? credential?.rawId;
      const presentedId = normalizeCredentialIdString(credentialId);
      if (!presentedId) {
        throw new InvalidPayloadError({ reason: 'credential id format is invalid' });
      }
      const readAccountability = SERVICE_ACCOUNTABILITY;

      const challenge = await consumeChallenge(
        context,
        accountability,
        userId,
        'authentication',
        challengeCollection,
        exceptions,
        attemptId,
        'drytest',
      );

      if (!challenge?.parsed) {
        throw new InvalidPayloadError({ reason: 'authentication challenge is missing or invalid' });
      }
      const parsedChallenge = expectObject(challenge.parsed ?? null, 'authentication challenge is invalid');
      const parsedOrigins = Array.isArray((parsedChallenge as any).origins)
        ? (parsedChallenge as any).origins.filter((origin: any) => typeof origin === 'string' && origin.trim())
        : [];
      const parsedRpId =
        typeof (parsedChallenge as any).rpId === 'string' ? (parsedChallenge as any).rpId.trim() : '';
      if (parsedOrigins.length === 0) {
        throw new InvalidPayloadError({ reason: 'challenge origins are missing or invalid' });
      }
      if (!parsedRpId) {
        throw new InvalidPayloadError({ reason: 'challenge rpId is missing or invalid' });
      }

      const allowedIds = ((parsedChallenge as any).allowedCredentialIds ?? [])
        .map((id: any) => normalizeCredentialIdString(id))
        .filter(Boolean);
      if (allowedIds.length > 0 && !allowedIds.some((id: string | null) => credentialIdsMatch(id, presentedId))) {
        throw new InvalidCredentialsError({ reason: 'Credential was not issued an allowCredentials entry for this attempt' });
      }

      const matching = await findCredentialById(
        context,
        credentialsCollection,
        readAccountability,
        presentedId,
        exceptions,
        fieldMapResult,
      );
      if (!matching || `${matching.user}` !== `${userId}`) {
        throw new InvalidCredentialsError({ reason: 'Credential is not registered for this user' });
      }

      const storedCredentialId = normalizeCredentialIdString(matching.credential_id);
      const storedPublicKey = typeof matching.public_key === 'string' ? matching.public_key.trim() : null;
      if (!storedCredentialId || !storedPublicKey) {
        throw new InvalidCredentialsError({ reason: 'Stored credential is invalid' });
      }

      let publicKey: Uint8Array<ArrayBuffer>;
      let credentialBytes: Uint8Array<ArrayBuffer>;
      try {
        publicKey = toUint8ArrayFromBase64Url(storedPublicKey, 'public_key');
        credentialBytes = toUint8ArrayFromBase64Url(storedCredentialId, 'credential_id');
      } catch (error) {
        throw new InvalidCredentialsError({ reason: 'Stored credential is invalid' });
      }

      const verification = await serverFns.verifyAuthenticationResponse({
        response: credential,
        expectedChallenge: (parsedChallenge as any).challenge,
        expectedOrigin: parsedOrigins,
        expectedRPID: parsedRpId ?? config.rpId,
        credential: {
          id: storedCredentialId,
          publicKey,
          counter: matching.sign_count ?? 0,
          transports: Array.isArray(matching.transports)
            ? (matching.transports as AuthenticatorTransportFuture[])
            : undefined,
        },
        requireUserVerification: config.userVerification !== 'discouraged',
      });

      if (!verification.verified || !verification.authenticationInfo) {
        throw new InvalidCredentialsError({ reason: 'Authentication response could not be verified' });
      }

      logDev('info', '[webauthn][drytest/verify] success', {
        userId,
        credentialId: matching.credential_id,
        attemptId,
        requestId,
        debug_id: debugId,
      });

      const belongsToUser = `${matching.user}` === `${userId}`;
      await deleteChallengeById(
        context,
        SERVICE_ACCOUNTABILITY,
        challengeCollection,
        challenge.row.challenge_id ?? challenge.row.id ?? null,
        exceptions,
        logger,
      );
      const storedCounter =
        typeof matching.sign_count === 'number' && Number.isFinite(matching.sign_count) ? matching.sign_count : null;
      const newCounter =
        typeof verification.authenticationInfo?.newCounter === 'number' &&
        Number.isFinite(verification.authenticationInfo.newCounter)
          ? verification.authenticationInfo.newCounter
          : null;
      const transports = Array.isArray(matching.transports) ? matching.transports : null;
      const responseBody: Record<string, any> = {
        matched: belongsToUser,
        belongsToUser,
        match: belongsToUser,
        credential_id: matching.credential_id,
        credential_name: matching.nickname ?? 'Passkey',
        deviceType: matching.device_type ?? 'public-key',
        transports,
        storedCounter,
        newCounter,
        credential: {
          id: matching.credential_id,
          label: matching.nickname ?? 'Passkey',
          type: matching.device_type ?? 'public-key',
        },
      };
      if (!belongsToUser) {
        responseBody.error = 'credential_not_owned';
        responseBody.message = 'Credential is valid, but not registered under this user.';
      }
      respondOk(
        res,
        responseBody,
        { requestId },
      );
    } catch (error: any) {
      const message = (error as Error)?.message ?? 'WebAuthn drytest failed';
      if (error instanceof InvalidPayloadError || error instanceof ValidationError) {
        return respondError(res, 400, 'invalid_webauthn_response', message, {
          stage: 'verify',
          hint: 'rpId/origin/challenge/credentialId',
        },
        undefined,
        { debug_id: debugId, requestId: (req as any).webauthnRequestId ?? null });
      }

      if (error instanceof InvalidCredentialsError) {
        return respondError(res, 401, 'invalid_webauthn_credentials', message, {
          stage: 'verify',
          hint: 'rpId/origin/challenge/credentialId',
        },
        undefined,
        { debug_id: debugId, requestId: (req as any).webauthnRequestId ?? null });
      }

      handleError(error, res, next, logger, exceptions, verboseLogging, {
        requestId: (req as any).webauthnRequestId,
        route: 'drytest/verify',
        rpId: lastConfig?.rpId,
        hostname,
        diagnosticsAllowed,
        env: normalizedBaseEnv,
        debugId,
      });
    }
  }

  async function listCredentialsRoute(req: Request, res: Response, next: NextFunction) {
    const diagnosticsAllowed = diagnosticsAllowedForRequest(req, normalizedBaseEnv);
    let debugId: string | null = null;
    try {
      const requestId = ensureRequestId(req);
      debugId = ensureDebugId(req);
      const hostname = requestHostname(req);
      const { userId } = ensureLoggedIn(req, exceptions);
      const accountability = SERVICE_ACCOUNTABILITY;
      const storageStatus = await ensureStorage(req, 'credentials_list');
      const credentialsCollection = storageStatus.collections.credentials;
      const fieldMapResult = await getWebauthnCredentialsFieldMap(context, credentialsCollection);
      const credentials = await listCredentials(
        context,
        credentialsCollection,
        userId,
        accountability,
        exceptions,
        fieldMapResult,
      );
      const sanitized = credentials.map((entry) => {
        const id = normalizeCredentialIdString(entry.credential_id) ?? entry.credential_id;
        const type = toCredentialType(entry.device_type);
        return {
          id,
          label: entry.nickname ?? 'Passkey',
          type,
          created_at: entry.created_at ?? null,
          last_used_at: entry.last_used_at ?? entry.updated_at ?? null,
        };
      });
      logDev('debug', '[webauthn][credentials] list', {
        requestId,
        hostname,
        count: sanitized.length,
        debug_id: debugId,
      });
      respondOk(res, { credentials: sanitized }, { requestId });
    } catch (error) {
      handleError(error, res, next, logger, exceptions, verboseLogging, {
        requestId: (req as any).webauthnRequestId,
        route: 'credentials',
        hostname: requestHostname(req),
        diagnosticsAllowed,
        env: normalizedBaseEnv,
        debugId,
      });
    }
  }

  async function deleteCredential(req: Request, res: Response, next: NextFunction) {
    let hostname: string | null = null;
    let debugId: string | null = null;
    const diagnosticsAllowed = diagnosticsAllowedForRequest(req, normalizedBaseEnv);
    try {
      const requestId = ensureRequestId(req);
      debugId = ensureDebugId(req);
      hostname = requestHostname(req);
      const { userId } = ensureLoggedIn(req, exceptions);
      const { id } = req.params ?? {};
      const credentialId = toBase64Url(id);
      if (!credentialId) {
        throw new InvalidPayloadError({ reason: 'credential id is required' });
      }
      const accountability = (req as any).accountability ?? { user: userId };
      const storageStatus = await ensureStorage(req, 'credentials_delete');
      const credentialsCollection = storageStatus.collections.credentials;
      const fieldMapResult = await getWebauthnCredentialsFieldMap(context, credentialsCollection);
      const fieldMap = fieldMapResult.fieldMap;
      const items = await createItemsService(credentialsCollection, context, accountability, exceptions);
      const lookup = await items.readByQuery({
        filter: { [fieldMap.credentialIdField]: { _eq: credentialId } },
        limit: 1,
        fields: [fieldMap.credentialIdField, fieldMap.userField],
      });
      const record = (lookup?.data ?? lookup ?? [])[0];
      const recordUser = record ? record[fieldMap.userField] : null;
      if (!record || `${recordUser}` !== `${userId}`) {
        throw new ForbiddenError('Credential not found for this user');
      }
      await items.deleteByQuery({ filter: { [fieldMap.credentialIdField]: { _eq: credentialId } }, limit: 1 });
      respondOk(res, { deleted: credentialId }, { requestId, debug_id: debugId });
    } catch (error) {
      handleError(error, res, next, logger, exceptions, verboseLogging, {
        requestId: (req as any).webauthnRequestId,
        route: 'credentials/delete',
        hostname,
        diagnosticsAllowed,
        env: normalizedBaseEnv,
        debugId,
      });
    }
  }

  async function health(req: Request, res: Response, next: NextFunction) {
    const requestId = ensureRequestId(req);
    const meta = { requestId };
    const allowDiagnostics = diagnosticsAllowedForRequest(req, normalizedBaseEnv);
    const body: any = {
      version: EXT_VERSION,
      build: BUILD_INFO,
      config: { available: false },
      crypto: { available: typeof randomUUID === 'function' },
      storage: { available: false },
      runtime: { extension_root_path: EXTENSION_DIR, process_pid: process.pid, mount_path: '/webauthn' },
    };

    try {
      const { config, path, defaultsApplied } = resolveConfigForRequest(req, normalizedBaseEnv, logger) as any;
      body.config = { available: true };
      if (allowDiagnostics) {
        body.config.rpId = config.rpId;
        body.config.origins = config.origins.length;
        body.config.userVerification = config.userVerification;
        body.envPath = path ?? null;
        body.appliedDefaults = defaultsApplied ?? [];
      }
    } catch (error: any) {
      const missing = error instanceof ConfigError && Array.isArray((error as any).missing) ? (error as any).missing : [];
      body.config = { available: false };
      if (allowDiagnostics) {
        body.config.missing = missing;
        if (error?.message) {
          body.reason = error.message;
        }
      }
    }

    try {
      const status = await ensureStorage(req, 'health');
      await cleanupChallenges(context, status.collections.challenges, exceptions, logger).catch(() => undefined);
      body.storage = {
        available: status.available,
        schema_version: status.schemaVersion,
        collections: status.collections,
        provisioned: status.provisioned,
      };
      if (allowDiagnostics) {
        body.storage.missing =
          status.missingCollections.length === 0 && status.missingFields.length === 0
            ? []
            : [...status.missingCollections, ...status.missingFields];
        if (`${normalizedBaseEnv['WEBAUTHN_DEBUG'] ?? ''}`.trim().toLowerCase() === 'true') {
          body.storage.required = {
            credentials: STORAGE_REQUIRED_CREDENTIAL_FIELDS,
            challenges: STORAGE_REQUIRED_CHALLENGE_FIELDS,
          };
        }
        body.storage.warnings = status.warnings ?? [];
        body.storage.optional_missing = status.optionalMissingFields ?? [];
        body.storage.optional_missing_by_collection = status.optionalMissingFieldsByCollection ?? {};
        body.storage.mismatched = status.mismatchedFields;
        body.storage.mismatched_by_collection = status.mismatchedFieldsByCollection;
        body.storage.provisionCommand = provisionCommand;
        body.storage.diagnostics = toStorageDiagnostics(status, req, normalizedBaseEnv);
        try {
          const credentialItems = await createItemsService(
            status.collections.credentials,
            context,
            SERVICE_ACCOUNTABILITY,
            exceptions,
          );
          const credentialLookup = await credentialItems.readByQuery({ limit: 1, fields: ['id'] });
          const credentialRows = (credentialLookup?.data ?? credentialLookup ?? []) as any[];
          const credentialRow = credentialRows[0];
          body.storage.credentials = {
            collection: status.collections.credentials,
            present: Array.isArray(credentialRows) && credentialRows.length > 0,
            first_id:
              credentialRow && typeof credentialRow === 'object'
                ? credentialRow.id ?? credentialRow.pk ?? null
                : null,
          };
        } catch (credentialCheckError: any) {
          body.storage.credentials = {
            collection: status.collections.credentials,
            present: false,
            error: credentialCheckError?.message ?? 'credential_check_failed',
          };
        }
      }
    } catch (error: any) {
      if (error instanceof StorageSchemaError) {
        const diagnostics = toStorageDiagnostics(error.result, req, normalizedBaseEnv);
        const hasMismatches = (error.result.mismatchedFields ?? []).length > 0;
        body.storage = {
          available: false,
          schema_version: error.result.schemaVersion,
          diagnostics: allowDiagnostics ? diagnostics : undefined,
          mismatched: hasMismatches ? error.result.mismatchedFields : undefined,
          warnings: allowDiagnostics ? error.result.warnings ?? [] : undefined,
          optional_missing: allowDiagnostics ? error.result.optionalMissingFields ?? [] : undefined,
          reason: error?.message ?? 'WebAuthn storage schema mismatch',
        };
        if (allowDiagnostics) {
          body.storage.missing = [
            ...(error.result.missingCollections ?? []),
            ...(error.result.missingFields ?? []),
          ];
          body.storage.mismatched = error.result.mismatchedFields ?? [];
          body.storage.mismatched_by_collection = error.result.mismatchedFieldsByCollection;
          body.storage.warnings = error.result.warnings ?? [];
          body.storage.optional_missing = error.result.optionalMissingFields ?? [];
          body.storage.optional_missing_by_collection = error.result.optionalMissingFieldsByCollection ?? {};
          body.storage.provisionCommand = provisionCommand;
          body.storage.reason = error?.message ?? null;
        } else if (hasMismatches) {
          body.storage.mismatched = error.result.mismatchedFields ?? [];
        }
      } else {
        body.storage = { available: false, reason: error?.message ?? 'storage check failed' };
      }
    }

    respondOk(res, body, meta);
  }

  async function diagnostics(req: Request, res: Response, next: NextFunction) {
    const requestId = ensureRequestId(req);
    const debugId = ensureDebugId(req);
    const allowDiagnostics = diagnosticsAllowedForRequest(req, normalizedBaseEnv);
    const meta = { requestId, debug_id: debugId };
    let diagConfig: WebAuthnConfig | null = null;

    if (!allowDiagnostics) {
      return respondError(
        res,
        403,
        'webauthn_diagnostics_disabled',
        'WebAuthn diagnostics disabled',
        { enabled: false },
        null,
        meta,
      );
    }

    const body: any = {
      version: EXT_VERSION,
      build: BUILD_INFO,
      router: ROUTER_ID,
      routes: REGISTERED_ROUTE_PATTERNS.map((route) => `/webauthn${route.startsWith('/') ? '' : '/'}${route}`),
    };

    try {
      const { config, path } = resolveConfigForRequest(req, normalizedBaseEnv, logger) as any;
      body.config = {
        rpId: config.rpId,
        origins: config.origins,
        timeoutMs: config.timeoutMs ?? config.timeout ?? null,
        userVerification: config.userVerification ?? null,
      };
      body.envPath = path ?? null;
      diagConfig = config;
    } catch (error: any) {
      body.config_error = {
        message: typeof error?.message === 'string' ? error.message : 'WebAuthn config unavailable',
        missing: Array.isArray((error as any)?.missing) ? (error as any).missing : [],
      };
    }

    try {
      const status = await ensureStorage(req, 'diagnostics');
      const diagnostics = toStorageDiagnostics(status, req, normalizedBaseEnv);
      body.storage = {
        available: status.available,
        schema_version: status.schemaVersion,
        collections: status.collections,
        provisioned: status.provisioned,
        missing: diagnostics.missing ?? diagnostics.missing_fields ?? [],
        mismatched: diagnostics.mismatched ?? diagnostics.mismatched_fields ?? [],
        diagnostics,
        provisionCommand,
      };
    } catch (error: any) {
      if (error instanceof StorageSchemaError) {
        const diagnostics = toStorageDiagnostics(error.result, req, normalizedBaseEnv);
        body.storage = {
          available: false,
          schema_version: error.result.schemaVersion,
          diagnostics,
          missing: diagnostics.missing ?? diagnostics.missing_fields ?? [],
          mismatched: diagnostics.mismatched ?? diagnostics.mismatched_fields ?? [],
          provisionCommand,
          reason: error?.message ?? 'WebAuthn storage schema mismatch',
        };
      } else {
        body.storage = {
          available: false,
          provisionCommand,
          reason: error?.message ?? 'WebAuthn storage unavailable',
        };
      }
    }

    try {
      const fieldMap = await getCollectionFieldMap(context, CREDENTIALS_COLLECTION);
      const webauthnMapResult = await getWebauthnCredentialsFieldMap(context, CREDENTIALS_COLLECTION);
      const webauthnMap = webauthnMapResult.fieldMap;
      const fields = Array.from(fieldMap.values()).map((info) => ({
        field: info.name,
        type: info.type ?? null,
        required: info.required ?? false,
        primary: info.isPrimaryKey ?? false,
        special: info.special ?? null,
        interface: info.interface ?? null,
      }));

      const sampleConfig =
        diagConfig ??
        ({ rpId: 'diag.local', origins: [], timeoutMs: 120000, userVerification: 'preferred' } as WebAuthnConfig);
      const sampleExtracted = {
        credentialIdB64u: 'c2FtcGxlLWNyZWRlbnRpYWw',
        publicKeyB64u: 'cHVibGljLWtleQ',
        counter: 0,
        transports: [],
        aaguid: null,
        deviceType: null,
        backedUp: null,
        userAgent: 'diag',
        origin: null,
        rpId: sampleConfig.rpId,
        lastUsedAt: new Date().toISOString(),
      } as const;

      let plan: CredentialRecordDebug | null = null;
      try {
        const built = buildCredentialRecord(
          fieldMap,
          sampleExtracted,
          '00000000-0000-0000-0000-000000000000',
          sampleConfig,
          {
            nickname: 'Diag sample',
            origin: null,
            userAgent: 'diag',
            lastUsedAt: new Date().toISOString(),
          },
          webauthnMap,
        );
        plan = built.debug;
      } catch (planError: any) {
        body.credentials_schema_error = planError?.message ?? 'unable to map credential fields';
      }

      body.credentials_schema = {
        fields,
        intended_write_fields: plan?.includedFields ?? [],
        missing_required_fields: plan?.missingRequired ?? [],
        dropped_unknown_fields: plan?.droppedUnknown ?? [],
        type_conflicts: plan?.typeConflicts ?? [],
      };
    } catch (error: any) {
      body.credentials_schema_error = error?.message ?? 'unable to read credential schema';
    }

    respondOk(res, body, meta);
  }

  async function diagBuild(req: Request, res: Response, next: NextFunction) {
    const requestId = ensureRequestId(req);
    const debugId = ensureDebugId(req);
    respondOk(
      res,
      {
        router_id: ROUTER_ID,
        git_sha: process.env.GIT_SHA ?? 'unknown',
        required_credentials_fields: STORAGE_REQUIRED_CREDENTIAL_FIELDS,
        required_challenge_fields: STORAGE_REQUIRED_CHALLENGE_FIELDS,
      },
      { requestId, debug_id: debugId },
    );
  }

  async function schemaDiagnostics(req: Request, res: Response, next: NextFunction) {
    const requestId = ensureRequestId(req);
    const debugId = ensureDebugId(req);
    const meta = { requestId, debug_id: debugId };
    const debugEnabled = `${normalizedBaseEnv['WEBAUTHN_DEBUG'] ?? ''}`.trim().toLowerCase() === 'true';
    const callerIsAdmin = Boolean((req as any)?.accountability?.admin);

    if (!debugEnabled || !callerIsAdmin) {
      return respondError(
        res,
        403,
        'webauthn_diagnostics_disabled',
        'WebAuthn schema diagnostics restricted',
        { debug: debugEnabled, admin: callerIsAdmin },
        null,
        meta,
      );
    }

    try {
      const storageStatus = await ensureStorage(req, 'diag_schema');
      const { fieldMap, availableFields } = await getWebauthnCredentialsFieldMap(
        context,
        storageStatus.collections.credentials,
      );
      const sample = availableFields.slice(0, 50);
      respondOk(
        res,
        {
          collection: storageStatus.collections.credentials,
          fieldMap,
          availableFieldsCount: availableFields.length,
          availableFieldsSample: sample,
        },
        meta,
      );
    } catch (error) {
      handleError(error, res, next, logger, exceptions, verboseLogging, {
        requestId,
        route: 'diag/schema',
        rpId: null,
        hostname: requestHostname(req),
        diagnosticsAllowed: true,
        env: normalizedBaseEnv,
        debugId,
      });
    }
  }

  async function matchDiagnostics(req: Request, res: Response, next: NextFunction) {
    const requestId = ensureRequestId(req);
    const debugId = ensureDebugId(req);
    const meta = { requestId, debug_id: debugId };
    const debugEnabled = `${normalizedBaseEnv['WEBAUTHN_DEBUG'] ?? ''}`.trim().toLowerCase() === 'true';
    const callerIsAdmin = Boolean((req as any)?.accountability?.admin);

    if (!debugEnabled || !callerIsAdmin) {
      return respondError(
        res,
        403,
        'webauthn_diagnostics_disabled',
        'WebAuthn match diagnostics restricted',
        { debug: debugEnabled, admin: callerIsAdmin },
        null,
        meta,
      );
    }

    try {
      const { userId } = ensureLoggedIn(req, exceptions);
      const presentedIdRaw = (req.query?.presentedId ?? req.query?.id ?? req.query?.credentialId) as string | undefined;
      const presentedId = normalizeCredentialIdString(presentedIdRaw);
      if (!presentedId) {
        return respondError(
          res,
          400,
          'invalid_webauthn_response',
          'presentedId is required',
          { stage: 'diag_match' },
          null,
          meta,
        );
      }

      const storageStatus = await ensureStorage(req, 'diag_match');
      const credentialsCollection = storageStatus.collections.credentials;
      const fieldMapResult = await getWebauthnCredentialsFieldMap(context, credentialsCollection);
      const credentials = await listCredentials(
        context,
        credentialsCollection,
        userId,
        { admin: true },
        exceptions,
        fieldMapResult,
      );
      const match = credentials.some((entry) => credentialIdsMatch(entry.credential_id, presentedId));
      const storedPrefixes = credentials
        .map((entry) => toCredentialIdPrefix(normalizeCredentialIdString(entry.credential_id)))
        .filter(Boolean);

      respondOk(
        res,
        {
          match,
          resolvedUserId: userId,
          storedCount: credentials.length,
          presentedIdPrefix: toCredentialIdPrefix(presentedId),
          storedPrefixes,
        },
        meta,
      );
    } catch (error) {
      handleError(error, res, next, logger, exceptions, verboseLogging, {
        requestId,
        route: 'diag/match',
        rpId: null,
        hostname: requestHostname(req),
        diagnosticsAllowed: true,
        env: normalizedBaseEnv,
        debugId,
      });
    }
  }

  return {
    registrationOptions,
    registrationVerify,
    authenticationOptions,
    authenticationVerify,
    drytestOptions,
    drytestVerify,
    listCredentials: listCredentialsRoute,
    deleteCredential,
    diagBuild,
    diagnostics,
    schemaDiagnostics,
    matchDiagnostics,
    health,
  } as const;
}
