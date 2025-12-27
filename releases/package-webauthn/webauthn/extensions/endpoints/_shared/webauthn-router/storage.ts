import { randomUUID } from 'node:crypto';
import type { Request } from 'express';
import { assertNoDriftConfig, CHALLENGES_COLLECTION, CREDENTIALS_COLLECTION, resolveStorageCollections } from './storage-names.js';
import type { LoggerLike } from './types.js';

export type StorageCheckResult = {
  available: boolean;
  provisioned: boolean;
  missingCollections: string[];
  missingFields: string[];
  missingFieldsByCollection: Record<string, string[]>;
  optionalMissingFields: string[];
  optionalMissingFieldsByCollection: Record<string, string[]>;
  mismatchedFields: string[];
  mismatchedFieldsByCollection: Record<string, string[]>;
  collections: { credentials: string; challenges: string };
  schemaVersion: number;
  issues: string[];
  warnings: string[];
};

export class StorageSchemaError extends Error {
  result: StorageCheckResult;
  directusUrl: string | null;
  constructor(result: StorageCheckResult, directusUrl: string | null, message?: string) {
    super(message ?? 'WebAuthn storage schema invalid');
    this.name = 'StorageSchemaError';
    this.result = result;
    this.directusUrl = directusUrl;
  }
}

export const REQUIRED_CREDENTIAL_FIELDS = [
  'credential_id',
  'public_key',
  'user',
  'sign_count',
];

export const REQUIRED_CHALLENGE_FIELDS = [
  'challenge_id',
  'challenge',
  'type',
  'expires_at',
];

export const OPTIONAL_CREDENTIAL_FIELDS = [
  'transports',
  'aaguid',
  'device_type',
  'backed_up',
  'nickname',
  'user_agent',
  'origin',
  'rp_id',
  'last_used_at',
  'created_at',
  'updated_at',
  'credential_uuid',
  'cose_alg',
  'email',
];

export const OPTIONAL_CHALLENGE_FIELDS = [
  'user',
  'origin',
  'rp_id',
  'used_at',
  'created_at',
];

export const SCHEMA_VERSION = 1;

function collectionExists(schema: any, collection: string): boolean {
  if (!schema) return false;
  const collections = (schema as any).collections;
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

function getField(schema: any, collection: string, field: string): any | null {
  if (!schema) return null;
  const fields = (schema as any).fields;
  const key = `${collection}.${field}`;

  if (fields instanceof Map) {
    return (fields.get(key) ?? fields.get(field)) ?? null;
  }

  if (typeof fields === 'object') {
    return (fields as any)[key] ?? (fields as any)[field] ?? null;
  }

  return null;
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

function maybeProvisionInMemory(schema: any, logger?: LoggerLike) {
  if (!schema || typeof schema !== 'object') return false;
  let changed = false;

  if (typeof schema.collections === 'object') {
    const collections = schema.collections as Record<string, any>;
    if (!collections[CREDENTIALS_COLLECTION]) {
      collections[CREDENTIALS_COLLECTION] = { note: `webAuthn schema v${SCHEMA_VERSION}` };
      changed = true;
    }
    if (!collections[CHALLENGES_COLLECTION]) {
      collections[CHALLENGES_COLLECTION] = { note: `webAuthn schema v${SCHEMA_VERSION}` };
      changed = true;
    }
  }

  if (typeof schema.fields === 'object') {
    const fields = schema.fields as Record<string, any>;
    for (const field of REQUIRED_CREDENTIAL_FIELDS) {
      const key = `${CREDENTIALS_COLLECTION}.${field}`;
      if (!fields[key]) {
        fields[key] = {};
        changed = true;
      }
    }
    for (const field of REQUIRED_CHALLENGE_FIELDS) {
      const key = `${CHALLENGES_COLLECTION}.${field}`;
      if (!fields[key]) {
        fields[key] = {};
        changed = true;
      }
    }
  }

  if (changed) {
    logger?.info?.('[WEBAUTHN][PROVISION] Patched in-memory schema for WebAuthn collections');
  }

  return changed;
}

function directusUrlFromEnv(env: Record<string, string | undefined>): string | null {
  const keys = ['DIRECTUS_URL', 'DIRECTUS_API', 'DIRECTUS_BASE_URL', 'DIRECTUS_URL_DEV', 'DIRECTUS_API_DEV'];
  for (const key of keys) {
    const value = env?.[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

type DirectusServiceCtors = {
  CollectionsService?: new (options: any) => any;
  FieldsService?: new (options: any) => any;
  ItemsService?: new (collection: string, options: any) => any;
};

type DirectusContext = {
  services?: DirectusServiceCtors;
  getSchema?: () => Promise<any>;
  database?: any;
  knex?: any;
};

async function safeGetSchema(context: DirectusContext, logger?: LoggerLike) {
  if (typeof context.getSchema !== 'function') return undefined;
  try {
    return await context.getSchema();
  } catch (error) {
    logger?.debug?.('[WEBAUTHN][STORAGE] getSchema failed, continuing with admin service lookup', { error });
    return undefined;
  }
}

async function fetchCollectionFields(
  context: DirectusContext,
  collection: string,
  logger?: LoggerLike,
): Promise<{ exists: boolean; fields: Set<string> } | null> {
  const services = context.services;
  const knex = (context as any).database ?? (context as any).knex ?? (context as any).databaseClient;
  const options = {
    accountability: { admin: true },
    schema: await safeGetSchema(context, logger),
    knex,
  } as any;

  if (services?.CollectionsService && services?.FieldsService) {
    try {
      const collectionsService = new services.CollectionsService(options);
      await collectionsService.readOne(collection);
    } catch (error: any) {
      if (logger?.debug) logger.debug(`[WEBAUTHN][STORAGE] Collection check failed for ${collection}`, { error });
      return { exists: false, fields: new Set<string>() };
    }

    try {
      const fieldsService = new services.FieldsService(options);
      const raw = await fieldsService.readAll(collection, { limit: -1 });
      const entries: any[] = Array.isArray(raw) ? raw : raw?.data ?? [];
      const fieldNames = entries
        .map((entry) => (entry?.field ?? entry?.name ?? entry?.id ?? '').toString())
        .filter((name) => name.trim() !== '');
      return { exists: true, fields: new Set(fieldNames) };
    } catch (error: any) {
      if (logger?.debug) logger.debug(`[WEBAUTHN][STORAGE] Field check failed for ${collection}`, { error });
      return { exists: true, fields: new Set<string>() };
    }
  }

  const ItemsService = services?.ItemsService;
  if (!ItemsService) {
    logger?.debug?.('[WEBAUTHN][STORAGE] ItemsService unavailable; cannot inspect collections via API');
    return null;
  }

  try {
    const collections = new ItemsService('directus_collections', options);
    const collectionResult = await collections.readByQuery({
      filter: { collection: { _eq: collection } },
      limit: 1,
    });
    const collectionExists = Array.isArray((collectionResult as any)?.data)
      ? (collectionResult as any).data.length > 0
      : Boolean((collectionResult as any)?.length);

    if (!collectionExists) {
      return { exists: false, fields: new Set<string>() };
    }

    const fieldsService = new ItemsService('directus_fields', options);
    const rawFields = await fieldsService.readByQuery({
      filter: { collection: { _eq: collection } },
      limit: -1,
    });
    const entries: any[] = Array.isArray(rawFields) ? rawFields : (rawFields as any)?.data ?? [];
    const names = entries
      .map((entry) => (entry?.field ?? entry?.field_name ?? entry?.id ?? '').toString())
      .filter((name) => name.trim() !== '');
    return { exists: true, fields: new Set(names) };
  } catch (error: any) {
    logger?.debug?.('[WEBAUTHN][STORAGE] Failed to read collections/fields via ItemsService', {
      collection,
      error,
    });
    return { exists: false, fields: new Set<string>() };
  }
}

export async function ensureWebauthnStorage(
  context: DirectusContext,
  env: Record<string, string | undefined>,
  logger?: LoggerLike,
): Promise<StorageCheckResult> {
  assertNoDriftConfig(env, logger);
  const { credentials, challenges } = resolveStorageCollections();
  const credentialFields = await fetchCollectionFields(context, credentials, logger);
  const challengeFields = await fetchCollectionFields(context, challenges, logger);
  const schema = credentialFields && challengeFields ? {} : (await context.getSchema?.()) ?? {};

  let missingCollections: string[] = [];
  let missingFields: string[] = [];
  let missingFieldsByCollection: Record<string, string[]> = {};
  let optionalMissingFields: string[] = [];
  let optionalMissingFieldsByCollection: Record<string, string[]> = {};
  let mismatchedFields: string[] = [];
  let mismatchedFieldsByCollection: Record<string, string[]> = {};

  const ensureStatus = () => {
    missingCollections = [];
    missingFields = [];
    missingFieldsByCollection = { [credentials]: [], [challenges]: [] };
    optionalMissingFields = [];
    optionalMissingFieldsByCollection = { [credentials]: [], [challenges]: [] };
    mismatchedFields = [];
    mismatchedFieldsByCollection = { [credentials]: [], [challenges]: [] };
    const usingServices = Boolean(credentialFields && challengeFields);

    const collectionStates = usingServices
      ? [
          { name: credentials, meta: credentialFields },
          { name: challenges, meta: challengeFields },
        ]
      : null;

    if (collectionStates) {
      for (const { name, meta } of collectionStates) {
        if (!meta?.exists) missingCollections.push(name);
      }
      if (missingCollections.length === 0) {
        const credentialMisses = REQUIRED_CREDENTIAL_FIELDS.filter((field) => !credentialFields?.fields.has(field)).map(
          (field) => `${credentials}.${field}`,
        );
        const challengeMisses = REQUIRED_CHALLENGE_FIELDS.filter((field) => !challengeFields?.fields.has(field)).map(
          (field) => `${challenges}.${field}`,
        );
        const credentialOptionalMisses = OPTIONAL_CREDENTIAL_FIELDS.filter((field) => !credentialFields?.fields.has(field)).map(
          (field) => `${credentials}.${field}`,
        );
        const challengeOptionalMisses = OPTIONAL_CHALLENGE_FIELDS.filter((field) => !challengeFields?.fields.has(field)).map(
          (field) => `${challenges}.${field}`,
        );
        missingFieldsByCollection[credentials] = credentialMisses;
        missingFieldsByCollection[challenges] = challengeMisses;
        missingFields.push(...credentialMisses, ...challengeMisses);
        optionalMissingFieldsByCollection[credentials] = credentialOptionalMisses;
        optionalMissingFieldsByCollection[challenges] = challengeOptionalMisses;
        optionalMissingFields.push(...credentialOptionalMisses, ...challengeOptionalMisses);
      }
      mismatchedFieldsByCollection[credentials] = [];
      mismatchedFieldsByCollection[challenges] = [];
      mismatchedFields = [];
      return;
    }

    if (!collectionExists(schema, credentials)) missingCollections.push(credentials);
    if (!collectionExists(schema, challenges)) missingCollections.push(challenges);
    if (missingCollections.length === 0) {
      const credentialFieldMisses = detectMissingFields(schema, credentials, REQUIRED_CREDENTIAL_FIELDS);
      const challengeFieldMisses = detectMissingFields(schema, challenges, REQUIRED_CHALLENGE_FIELDS);
      const credentialOptionalMisses = detectMissingFields(schema, credentials, OPTIONAL_CREDENTIAL_FIELDS);
      const challengeOptionalMisses = detectMissingFields(schema, challenges, OPTIONAL_CHALLENGE_FIELDS);
      missingFieldsByCollection[credentials] = credentialFieldMisses;
      missingFieldsByCollection[challenges] = challengeFieldMisses;
      missingFields.push(...credentialFieldMisses, ...challengeFieldMisses);
      optionalMissingFieldsByCollection[credentials] = credentialOptionalMisses;
      optionalMissingFieldsByCollection[challenges] = challengeOptionalMisses;
      optionalMissingFields.push(...credentialOptionalMisses, ...challengeOptionalMisses);

      mismatchedFieldsByCollection[credentials] = [];
      mismatchedFieldsByCollection[challenges] = [];
      mismatchedFields = [];
    }
  };

  ensureStatus();
  let provisioned = false;

  if (missingCollections.length || missingFields.length) {
    provisioned = maybeProvisionInMemory(schema, logger);
    if (provisioned) ensureStatus();
  }

  const issues = [
    ...missingCollections.map((name) => `${name} collection is missing`),
    ...missingFields.map((name) => `${name} is missing`),
  ];
  const warnings = [
    ...optionalMissingFields.map((name) => `${name} optional field is missing`),
  ];
  const available = missingCollections.length === 0 && missingFields.length === 0;
  const result: StorageCheckResult = {
    available,
    provisioned,
    missingCollections,
    missingFields,
    missingFieldsByCollection,
    optionalMissingFields,
    optionalMissingFieldsByCollection,
    mismatchedFields,
    mismatchedFieldsByCollection,
    collections: { credentials, challenges },
    schemaVersion: SCHEMA_VERSION,
    issues,
    warnings,
  };

  if (warnings.length > 0) {
    logger?.debug?.('[WEBAUTHN][STORAGE] optional fields missing', {
      warnings,
      optional_missing_by_collection: optionalMissingFieldsByCollection,
    });
  }

  if (!available) {
    const directusUrl = directusUrlFromEnv(env);
    const message = issues[0] ?? 'WebAuthn storage schema invalid';
    throw new StorageSchemaError(result, directusUrl, message);
  }

  return result;
}

export function toStorageDiagnostics(result: StorageCheckResult, req: Request | null, env: Record<string, string | undefined>) {
  return {
    directus_url: directusUrlFromEnv(env),
    collections_checked: [result.collections.credentials, result.collections.challenges],
    missing_collections: result.missingCollections,
    missing_fields: result.missingFields,
    missing_fields_by_collection: result.missingFieldsByCollection,
    optional_missing_fields: result.optionalMissingFields,
    optional_missing_fields_by_collection: result.optionalMissingFieldsByCollection,
    mismatched_fields: result.mismatchedFields,
    mismatched_fields_by_collection: result.mismatchedFieldsByCollection,
    expected_schema_version: result.schemaVersion,
    request_id: (req as any)?.webauthnRequestId ?? randomUUID(),
    issues: result.issues,
    warnings: result.warnings,
    missing: [...(result.missingCollections ?? []), ...(result.missingFields ?? [])],
    mismatched: result.mismatchedFields ?? [],
  };
}
