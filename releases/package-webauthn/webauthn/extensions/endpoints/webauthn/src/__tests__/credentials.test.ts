import { describe, expect, it } from 'vitest';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import registerEndpoint, { __testables } from '../index.js';

const { toAllowCredentials } = __testables;

describe('toAllowCredentials', () => {
  it('creates allowCredentials entries for valid stored credentials', () => {
    const credentialId = isoBase64URL.fromBuffer(Buffer.from('cred-1'));
    const result = toAllowCredentials([
      {
        id: '1',
        credential_id: credentialId,
        public_key: credentialId,
        user: 'user-1',
        transports: ['internal'],
      },
    ] as any);

    expect(result).toHaveLength(1);
    expect(typeof result[0].id).toBe('string');
    expect(result[0].transports).toEqual(['internal']);
  });

  it('skips credentials with invalid ids', () => {
    const result = toAllowCredentials([
      { id: '1', credential_id: '***', public_key: 'abc', user: 'user-1' },
    ] as any);

    expect(result).toHaveLength(0);
  });
});
