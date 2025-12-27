/**
 * WebAuthn configuration loader with host-aware env resolution.
 */
import type { Request } from 'express';
import { readFileSync, statSync } from 'fs';
import { assertNoDriftConfig, CREDENTIALS_COLLECTION } from './storage-names.js';

export interface WebAuthnConfig {
  rpId: string;
  rpName: string;
  origin: string;
  origins: string[];
  timeoutMs: number;
  userVerification: 'preferred' | 'required' | 'discouraged';
  mode: 'dev' | 'prod' | 'unknown';
  storageCollection: string;
}

export type HostEnvEntry = { env: Record<string, string | undefined>; mtimeMs: number | null; path: string | null };

export const hostEnvCache = new Map<string, HostEnvEntry>();
export const missingEnvNotified = new Set<string>();

export function parseEnvFile(path: string): Record<string, string> {
  const contents = readFileSync(path, 'utf8');
  const results: Record<string, string> = {};

  for (const rawLine of contents.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const line = trimmed.startsWith('export ')
      ? trimmed.slice('export '.length).trim()
      : trimmed;

    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1) continue;

    const key = line.slice(0, separatorIndex).trim();
    if (!key) continue;

    let value = line.slice(separatorIndex + 1).trim();
    value = value.replace(/^["']/, '').replace(/["']$/, '');

    results[key] = value;
  }

  return results;
}

function normalizeEnv(baseEnv: Record<string, string | undefined>) {
  return { ...process.env, ...baseEnv } as Record<string, string | undefined>;
}

function envPathsFromConfig(env: Record<string, string | undefined>): string[] {
  const candidates = [env.WEBAUTHN_ENV_PATHS, env.WEBAUTHN_ENV_FILE].filter(Boolean) as string[];
  const paths = [] as string[];

  for (const candidate of candidates) {
    for (const raw of candidate.split(',')) {
      const trimmed = raw.trim();
      if (!trimmed) continue;
      paths.push(trimmed);
    }
  }

  return Array.from(new Set(paths));
}

export function requestHostname(req: Request): string | null {
  if (typeof req.hostname === 'string' && req.hostname.trim()) return req.hostname.trim().toLowerCase();

  const hostHeader = req.get('host');
  if (!hostHeader) return null;

  try {
    const parsed = new URL(`http://${hostHeader}`);
    return parsed.hostname.toLowerCase();
  } catch (error) {
    return hostHeader.split(':')[0]?.toLowerCase() ?? null;
  }
}

function resolveMode(baseEnv: Record<string, string | undefined>): WebAuthnConfig['mode'] {
  const value = `${baseEnv?.WEBAUTHN_MODE ?? ''}`.trim().toLowerCase();
  if (value === 'dev' || value === 'development') return 'dev';
  if (value === 'prod' || value === 'production') return 'prod';
  return 'unknown';
}

function toOrigins(originText: string, rpId: string): string[] {
  const entries = originText
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => (entry.startsWith('http') ? entry : `https://${entry}`));

  const origins = [] as string[];
  for (const entry of entries) {
    try {
      const parsed = new URL(entry);
      if (parsed.protocol !== 'https:') continue;
      if (parsed.pathname !== '/' || parsed.search || parsed.hash) continue;
      const hostMatches = parsed.hostname === rpId || parsed.hostname.endsWith(`.${rpId}`);
      if (!hostMatches) continue;
      origins.push(parsed.origin);
    } catch (error) {
      continue;
    }
  }
  return Array.from(new Set(origins));
}

function deriveOriginFromRequest(req: Request, rpId: string): string | null {
  const hostname = requestHostname(req) ?? rpId;
  if (!hostname) return null;
  return `https://${hostname}`;
}

function normalizeOrigin(origin: string | undefined | null): string | null {
  if (!origin) return null;
  try {
    const candidate = origin.startsWith('http') ? origin : `https://${origin}`;
    const parsed = new URL(candidate);
    if (parsed.protocol !== 'https:') return null;
    if (parsed.pathname && parsed.pathname !== '/') return null;
    if (parsed.search || parsed.hash) return null;
    return parsed.origin;
  } catch (error) {
    return null;
  }
}

function deriveOriginFromEnv(env: Record<string, string | undefined>, rpId: string): string | null {
  const candidates = [
    env.WEBAUTHN_ORIGINS,
    env.WEBAUTHN_ORIGIN,
    env.PUBLIC_URL,
    env.APP_BASE_URL,
    env.DIRECTUS_BASE_URL,
    env.DIRECTUS_URL,
    env.DIRECTUS_API,
  ];
  for (const candidate of candidates) {
    const normalized = normalizeOrigin(candidate);
    if (normalized) return normalized;
  }

  if (rpId) {
    const rpOrigin = normalizeOrigin(`https://${rpId}`);
    if (rpOrigin) return rpOrigin;
  }

  return null;
}

export function envForHost(
  hostname: string | null,
  baseEnv: Record<string, string | undefined>,
  logger?: { warn?: (...args: any[]) => void; info?: (...args: any[]) => void },
): HostEnvEntry {
  const mergedBase = normalizeEnv(baseEnv);
  const envPaths = envPathsFromConfig(mergedBase);
  if (envPaths.length === 0) return { env: mergedBase, mtimeMs: null, path: null };

  const cacheKey = `${hostname ?? 'default'}:${envPaths.join('|')}`;
  const cache = hostEnvCache.get(cacheKey);

  for (const envPath of envPaths) {
    let stats;
    try {
      stats = statSync(envPath);
    } catch (error: any) {
      continue;
    }

    if (!stats.isFile()) continue;

    if (cache && cache.path === envPath && cache.mtimeMs === stats.mtimeMs) {
      return cache;
    }

    const merged = { ...mergedBase, ...parseEnvFile(envPath) };
    const entry: HostEnvEntry = { env: merged, mtimeMs: stats.mtimeMs, path: envPath };
    hostEnvCache.set(cacheKey, entry);
    logger?.info?.(`Loaded WebAuthn configuration from ${envPath}`);
    return entry;
  }

  if (!missingEnvNotified.has(cacheKey)) {
    if (envPaths.length > 0) {
      const hostLabel = hostname ? ` for ${hostname}` : '';
      logger?.warn?.(
        `Optional env files [${envPaths.join(', ')}] not found${hostLabel}; using in-memory environment values instead`,
      );
    }
    missingEnvNotified.add(cacheKey);
  }

  hostEnvCache.set(cacheKey, { env: mergedBase, mtimeMs: null, path: null });
  return { env: mergedBase, mtimeMs: null, path: null };
}

export function getWebAuthnServiceOrError(
  req: Request,
  baseEnv: Record<string, string | undefined>,
  logger?: { warn?: (...args: any[]) => void; info?: (...args: any[]) => void; debug?: (...args: any[]) => void },
):
  | { ok: true; config: WebAuthnConfig; envPath: string | null; defaultsApplied: string[]; missing: string[] }
  | { ok: false; status: number; body: { ok: false; error: string; message: string; details?: Record<string, any> } } {
  const hostEnv = envForHost(requestHostname(req), baseEnv, logger);
  const merged = hostEnv.env;
  const defaultsApplied: string[] = [];
  const mode = resolveMode(merged);
  const isDev = mode === 'dev';

  assertNoDriftConfig(merged, logger);

  const rpId = `${merged.WEBAUTHN_RP_ID ?? ''}`.trim() || requestHostname(req) || '';
  if (!merged.WEBAUTHN_RP_ID && rpId) defaultsApplied.push('WEBAUTHN_RP_ID');
  const rpName = `${merged.WEBAUTHN_RP_NAME ?? ''}`.trim() || rpId;
  if (!merged.WEBAUTHN_RP_NAME && rpName) defaultsApplied.push('WEBAUTHN_RP_NAME');

  const originEnv = `${merged.WEBAUTHN_ORIGIN ?? merged.WEBAUTHN_ORIGINS ?? ''}`.trim();
  let origin = originEnv;
  if (!origin) {
    const derived = deriveOriginFromRequest(req, rpId) ?? deriveOriginFromEnv(merged, rpId);
    if (derived) {
      origin = derived;
      defaultsApplied.push('WEBAUTHN_ORIGINS');
    }
  }

  const storageCollection = CREDENTIALS_COLLECTION;

  const timeoutRaw = `${merged.WEBAUTHN_TIMEOUT_MS ?? ''}`.trim();
  const timeoutMs = timeoutRaw && Number(timeoutRaw) > 0 ? Number(timeoutRaw) : 60000;
  if (!timeoutRaw) defaultsApplied.push('WEBAUTHN_TIMEOUT_MS');

  const userVerificationRaw = `${merged.WEBAUTHN_USER_VERIFICATION ?? ''}`.trim().toLowerCase();
  const userVerification =
    userVerificationRaw === 'required' || userVerificationRaw === 'discouraged' ? userVerificationRaw : 'preferred';
  if (!userVerificationRaw) defaultsApplied.push('WEBAUTHN_USER_VERIFICATION');

  const missing = [] as string[];
  if (!rpId) missing.push('WEBAUTHN_RP_ID');
  if (!rpName) missing.push('WEBAUTHN_RP_NAME');
  if (!origin) missing.push('WEBAUTHN_ORIGIN');

  if (missing.length > 0) {
    if (isDev) {
      logger?.warn?.('[webauthn] configuration missing', {
        missing,
        derived: { rpId, origin },
        envPath: hostEnv.path,
        hostname: requestHostname(req),
      });
    }
    return {
      ok: false,
      status: 503,
      body: {
        ok: false,
        error: 'webauthn_not_configured',
        message: 'WebAuthn not configured for this host',
        details: { missing },
      },
    };
  }

  let origins = toOrigins(origin, rpId);
  if (origins.length === 0) {
    const fallbackOrigin = deriveOriginFromEnv(merged, rpId);
    if (fallbackOrigin) {
      origins = toOrigins(fallbackOrigin, rpId);
      if (origins.length > 0) {
        origin = fallbackOrigin;
        if (!originEnv) defaultsApplied.push('WEBAUTHN_ORIGINS');
      }
    }
  }

  if (origins.length === 0) {
    return {
      ok: false,
      status: 503,
      body: {
        ok: false,
        error: 'webauthn_not_configured',
        message: 'WebAuthn origin is invalid',
        details: { missing: ['WEBAUTHN_ORIGIN'] },
      },
    };
  }

  return {
    ok: true,
    config: {
      rpId,
      rpName,
      origin: origins[0],
      origins,
      timeoutMs,
      userVerification,
      mode,
      storageCollection,
    },
    envPath: hostEnv.path,
    defaultsApplied,
    missing,
  };
}

export function loadConfig(
  envOverrides: Record<string, string | undefined>,
  options?: { request?: Partial<Request>; logger?: { warn?: (...args: any[]) => void; info?: (...args: any[]) => void } },
): { config: WebAuthnConfig; env: Record<string, string | undefined>; defaultsApplied: string[]; envPath: string | null } {
  const req = (options?.request as Request) ??
    ({ hostname: null, get: () => null, protocol: 'https' } as unknown as Request);
  const outcome = getWebAuthnServiceOrError(req, envOverrides, options?.logger);
  if (outcome.ok === false) {
    const missing = (outcome.body as any)?.details?.missing ?? [];
    throw new ConfigError(outcome.body.message, missing);
  }

  const hostEnv = envForHost(requestHostname(req), envOverrides, options?.logger);
  return { config: outcome.config, env: hostEnv.env, defaultsApplied: outcome.defaultsApplied, envPath: hostEnv.path };
}

export class ConfigError extends Error {
  missing: string[];

  constructor(message: string, missing: string[] = []) {
    super(message);
    this.name = 'ConfigError';
    this.missing = missing;
  }
}

export function resolveConfigForRequest(
  req: Request,
  baseEnv: Record<string, string | undefined>,
  logger?: { warn?: (...args: any[]) => void; info?: (...args: any[]) => void; debug?: (...args: any[]) => void },
): { config: WebAuthnConfig; env: Record<string, string | undefined>; path: string | null; defaultsApplied: string[] } {
  const hostEnv = envForHost(requestHostname(req), baseEnv, logger);
  const outcome = getWebAuthnServiceOrError(req, baseEnv, logger);
  if (outcome.ok === false) {
    const missing = (outcome.body as any)?.details?.missing ?? [];
    throw new ConfigError(outcome.body.message, missing);
  }

  return { config: outcome.config, env: hostEnv.env, path: outcome.envPath, defaultsApplied: outcome.defaultsApplied };
}
