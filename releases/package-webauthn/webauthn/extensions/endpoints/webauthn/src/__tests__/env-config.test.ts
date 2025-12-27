import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../../../_shared/webauthn-router/env.js';

describe('loadConfig', () => {
  it('parses multiple origins and validates rpId alignment', () => {
    const { config } = loadConfig({
      WEBAUTHN_RP_ID: 'example.com',
      WEBAUTHN_RP_NAME: 'Example',
      WEBAUTHN_ORIGINS: 'https://example.com, https://auth.example.com ',
      WEBAUTHN_TIMEOUT_MS: '45000',
    });

    expect(config.rpId).toBe('example.com');
    expect(config.origins).toEqual(['https://example.com', 'https://auth.example.com']);
    expect(config.timeoutMs).toBe(45000);
  });

  it('derives host values in dev when rpId/origins are missing', () => {
    const mockRequest = {
      hostname: 'login.example.com',
      get: (key: string) => (key.toLowerCase() === 'host' ? 'login.example.com:8055' : null),
      protocol: 'https',
    } as any;
    const { config, defaultsApplied } = loadConfig(
      {
        WEBAUTHN_RP_NAME: 'Example',
        ENV: 'dev',
      },
      { request: mockRequest },
    );

    expect(config.rpId).toBe('login.example.com');
    expect(config.origins).toEqual(['https://login.example.com']);
    expect(defaultsApplied).toEqual(expect.arrayContaining(['WEBAUTHN_RP_ID', 'WEBAUTHN_ORIGIN']));
  });

  it('throws ConfigError with missing keys in prod', () => {
    expect(() =>
      loadConfig({
        WEBAUTHN_RP_NAME: 'Example',
        ENV: 'prod',
      }),
    ).toThrow(ConfigError);
  });
});
