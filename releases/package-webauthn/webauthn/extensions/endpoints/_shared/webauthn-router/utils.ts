import { isoBase64URL } from '@simplewebauthn/server/helpers';

export function normalizeToBuffer(value: unknown): Buffer | null {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value instanceof ArrayBuffer) return Buffer.from(new Uint8Array(value));
  if (value && typeof value === 'object' && Array.isArray((value as any).data)) {
    return Buffer.from((value as any).data);
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    try {
      const decoded = isoBase64URL.toBuffer(trimmed);
      return Buffer.from(decoded);
    } catch (error) {
      return null;
    }
  }
  if (Array.isArray(value)) return Buffer.from(value);
  return null;
}

export function toBase64Url(value: unknown): string | null {
  if (typeof value === 'string' && value.trim()) return value.trim();
  const buffer = normalizeToBuffer(value);
  if (!buffer) return null;
  const array = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength) as ArrayBuffer;
  const view = new Uint8Array(array);
  return isoBase64URL.fromBuffer(view);
}

export function redactCredentialPayload(payload: any): any {
  if (!payload || typeof payload !== 'object') return payload;
  const clone = { ...payload } as any;
  if (clone.response) {
    const redactedResponse: any = { ...clone.response };
    for (const key of ['authenticatorData', 'clientDataJSON', 'signature', 'attestationObject']) {
      if (key in redactedResponse) {
        redactedResponse[key] = typeof redactedResponse[key] === 'string' ? '[redacted]' : undefined;
      }
    }
    clone.response = redactedResponse;
  }
  return clone;
}

