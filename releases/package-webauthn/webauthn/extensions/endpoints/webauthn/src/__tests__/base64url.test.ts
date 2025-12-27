import { describe, expect, it } from 'vitest';
import { normalizeToBuffer, toBase64Url } from 'webauthn-router-shared';

describe('base64url helpers', () => {
  it('roundtrips buffer-like inputs', () => {
    const original = Buffer.from('hello-world');
    const encoded = toBase64Url(original);
    expect(typeof encoded).toBe('string');
    const decoded = normalizeToBuffer(encoded);
    expect(decoded?.toString()).toBe(original.toString());
  });

  it('accepts Uint8Array and ArrayBuffer', () => {
    const uint8 = new Uint8Array([1, 2, 3, 4]);
    const encoded = toBase64Url(uint8);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    const roundtrip = normalizeToBuffer(uint8.buffer);
    expect(roundtrip?.equals(Buffer.from(uint8))).toBe(true);
  });
});
