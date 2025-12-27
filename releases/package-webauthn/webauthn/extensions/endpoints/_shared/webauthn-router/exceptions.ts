export type WebauthnExceptions = {
  InvalidPayloadError?: new (input?: any) => any;
  InvalidCredentialsError?: new (input?: any) => any;
  ServiceUnavailableError?: new (input?: any) => any;
};

class WebauthnFallbackError extends Error {
  constructor(input?: any) {
    super(typeof input === 'string' ? input : input?.reason ?? 'WebAuthn error');
    Object.assign(this, input ?? {});
  }
}

export function resolveExceptions(exceptions?: Partial<WebauthnExceptions>): Required<WebauthnExceptions> {
  const fallback = WebauthnFallbackError as unknown as new (input?: any) => any;

  return {
    InvalidPayloadError: (exceptions?.InvalidPayloadError as any) ?? fallback,
    InvalidCredentialsError: (exceptions?.InvalidCredentialsError as any) ?? fallback,
    ServiceUnavailableError: (exceptions?.ServiceUnavailableError as any) ?? fallback,
  };
}
