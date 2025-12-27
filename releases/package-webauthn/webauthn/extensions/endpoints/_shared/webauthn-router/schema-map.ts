import type { ApiExtensionContext } from './types.js';

export type WebauthnCredentialsFieldMap = {
  credentialIdField: string;
  publicKeyField: string;
  userField: string;
  signCountField?: string;
  coseAlgField?: string;
  transportsField?: string;
  nicknameField?: string;
  createdAtField?: string;
  updatedAtField?: string;
  lastUsedAtField?: string;
  aaguidField?: string;
  deviceTypeField?: string;
  backedUpField?: string;
  originField?: string;
  userAgentField?: string;
  emailField?: string;
};

export class WebauthnSchemaMappingError extends Error {
  missing: string[];
  available: string[];

  constructor(message: string, missing: string[], available: string[]) {
    super(message);
    this.name = 'WebauthnSchemaMappingError';
    this.missing = missing;
    this.available = available;
  }
}

export type WebauthnCredentialsFieldMapResult = {
  fieldMap: WebauthnCredentialsFieldMap;
  availableFields: string[];
};

const cache: { value: WebauthnCredentialsFieldMapResult | null; expiresAt: number } = { value: null, expiresAt: 0 };

function pickField(priorities: string[], available: Set<string>): string | undefined {
  for (const candidate of priorities) {
    if (available.has(candidate)) return candidate;
  }
  return undefined;
}

async function loadFieldsViaServices(
  context: ApiExtensionContext,
  collection: string,
  servicesOverride?: Record<string, any> | null,
  schemaOverride?: any,
): Promise<{ fields: string[]; source: string }> {
  const services = servicesOverride ?? ((context as any).services ?? {});
  const schema = schemaOverride ?? (await (context as any)?.getSchema?.()) ?? undefined;
  const FieldsService = services?.FieldsService;
  if (FieldsService) {
    const svc = new FieldsService({ schema, accountability: { admin: true } });
    const records = await svc.readAll(collection);
    const fieldNames = (records ?? []).map((f: any) => f.field).filter(Boolean);
    if (fieldNames.length > 0) {
      return { fields: fieldNames, source: 'fields_service' };
    }
  }

  const ItemsService = services?.ItemsService;
  if (ItemsService) {
    const svc = new ItemsService('directus_fields', {
      schema,
      accountability: { admin: true },
      knex: (context as any).database ?? (context as any).knex ?? (context as any).databaseClient,
    });
    const result = await svc.readByQuery({ filter: { collection: { _eq: collection } }, fields: ['field'] });
    const rows = (result?.data ?? result ?? []) as any[];
    return { fields: rows.map((row) => row.field).filter(Boolean), source: 'directus_fields' };
  }

  throw new Error('No field service available');
}

export async function getWebauthnCredentialsFieldMap(
  context: ApiExtensionContext,
  collection = 'webauthn_credentials',
  servicesOverride?: Record<string, any> | null,
  schemaOverride?: any,
): Promise<WebauthnCredentialsFieldMapResult> {
  const now = Date.now();
  if (cache.value && cache.expiresAt > now) return cache.value;

  const { fields } = await loadFieldsViaServices(context, collection, servicesOverride, schemaOverride);
  const available = Array.from(new Set(fields)).sort();
  const availableSet = new Set(available);

  const fieldMap: WebauthnCredentialsFieldMap = {
    credentialIdField: pickField(['credential_id', 'credentialId', 'credentialID'], availableSet)!,
    publicKeyField: pickField(['public_key', 'publicKey', 'credential_public_key', 'credentialPublicKey'], availableSet)!,
    userField: pickField(['user', 'user_id', 'userId'], availableSet)!,
  };

  fieldMap.signCountField = pickField(['sign_count', 'signCount', 'counter'], availableSet);
  fieldMap.coseAlgField = pickField(['cose_alg', 'coseAlg', 'credential_alg', 'credentialAlg'], availableSet);
  fieldMap.transportsField = pickField(['transports'], availableSet);
  fieldMap.nicknameField = pickField(['nickname', 'label', 'name'], availableSet);
  fieldMap.createdAtField = pickField(['date_created', 'created_at', 'createdAt'], availableSet);
  fieldMap.updatedAtField = pickField(['updated_at', 'updatedAt', 'date_updated'], availableSet);
  fieldMap.lastUsedAtField = pickField(['last_used_at', 'lastUsedAt'], availableSet);
  fieldMap.aaguidField = pickField(['aaguid'], availableSet);
  fieldMap.deviceTypeField = pickField(['device_type', 'deviceType'], availableSet);
  fieldMap.backedUpField = pickField(['backed_up', 'backedUp'], availableSet);
  fieldMap.originField = pickField(['origin'], availableSet);
  fieldMap.userAgentField = pickField(['user_agent', 'userAgent'], availableSet);
  fieldMap.emailField = pickField(['email', 'user_email'], availableSet);

  const missing = Object.entries({
    credentialIdField: fieldMap.credentialIdField,
    publicKeyField: fieldMap.publicKeyField,
    userField: fieldMap.userField,
  })
    .filter(([, value]) => !value)
    .map(([key]) => key.replace('Field', ''));

  if (missing.length > 0) {
    throw new WebauthnSchemaMappingError('WebAuthn credential schema incomplete', missing, available);
  }

  cache.value = { fieldMap, availableFields: available };
  cache.expiresAt = now + 60_000;
  return cache.value;
}

export function invalidateWebauthnFieldMapCache() {
  cache.value = null;
  cache.expiresAt = 0;
}
