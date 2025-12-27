import type { LoggerLike } from './types.js';

export const CREDENTIALS_COLLECTION = 'webauthn_credentials';
export const CHALLENGES_COLLECTION = 'webauthn_challenges';

const DRIFT_KEYS = [
  'WEBAUTHN_STORAGE_COLLECTION',
  'WEBAUTHN_CREDENTIALS_COLLECTION',
  'WEBAUTHN_CHALLENGES_COLLECTION',
];

export function assertNoDriftConfig(env: Record<string, string | undefined>, logger?: LoggerLike) {
  const warnings: string[] = [];
  for (const key of DRIFT_KEYS) {
    const value = env?.[key];
    if (typeof value !== 'string' || !value.trim()) continue;
    const normalized = value.trim();
    if (normalized === CREDENTIALS_COLLECTION || normalized === CHALLENGES_COLLECTION) continue;
    warnings.push(`${key}=${normalized}`);
  }

  if (warnings.length > 0) {
    logger?.warn?.(
      `[WEBAUTHN][DRIFT] Ignoring collection overrides (${warnings.join(', ')}); using canonical collections`,
      {
        credentials_collection: CREDENTIALS_COLLECTION,
        challenges_collection: CHALLENGES_COLLECTION,
      },
    );
  }
}

export function resolveStorageCollections() {
  return {
    credentials: CREDENTIALS_COLLECTION,
    challenges: CHALLENGES_COLLECTION,
  } as const;
}
