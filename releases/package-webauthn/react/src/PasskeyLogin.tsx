import { useCallback, useMemo, useState } from 'react';

type PasskeyLoginProps = {
  baseUrl: string;
  email?: string;
};

type WebAuthnResponse<T> = {
  ok?: boolean;
  data?: T;
  error?: string;
  message?: string;
};

const encoder = new TextEncoder();

function bufferToBase64Url(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBuffer(value: string) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function credentialToJSON(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAssertionResponse | AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      ...(response instanceof AuthenticatorAttestationResponse
        ? {
            attestationObject: bufferToBase64Url(response.attestationObject),
          }
        : {
            authenticatorData: bufferToBase64Url((response as AuthenticatorAssertionResponse).authenticatorData),
            signature: bufferToBase64Url((response as AuthenticatorAssertionResponse).signature),
            userHandle: (response as AuthenticatorAssertionResponse).userHandle
              ? bufferToBase64Url((response as AuthenticatorAssertionResponse).userHandle as ArrayBuffer)
              : null,
          }),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function transformOptions(options: any) {
  const publicKey = { ...options } as PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions;
  if ('challenge' in publicKey && typeof publicKey.challenge === 'string') {
    publicKey.challenge = base64UrlToBuffer(publicKey.challenge);
  }
  if ('user' in publicKey && publicKey.user && typeof publicKey.user.id === 'string') {
    publicKey.user = { ...publicKey.user, id: base64UrlToBuffer(publicKey.user.id) };
  }
  if ('excludeCredentials' in publicKey && Array.isArray(publicKey.excludeCredentials)) {
    publicKey.excludeCredentials = publicKey.excludeCredentials.map((cred: any) => ({
      ...cred,
      id: base64UrlToBuffer(cred.id),
    }));
  }
  if ('allowCredentials' in publicKey && Array.isArray(publicKey.allowCredentials)) {
    publicKey.allowCredentials = publicKey.allowCredentials.map((cred: any) => ({
      ...cred,
      id: base64UrlToBuffer(cred.id),
    }));
  }
  return publicKey;
}

export function PasskeyLogin({ baseUrl, email }: PasskeyLoginProps) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [emailInput, setEmailInput] = useState(email ?? '');

  const base = useMemo(() => baseUrl.replace(/\/+$/, ''), [baseUrl]);

  const callApi = useCallback(async <T,>(path: string, payload: Record<string, unknown>) => {
    const response = await fetch(`${base}${path}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    const data = (await response.json()) as WebAuthnResponse<T>;
    if (!response.ok || data?.ok === false) {
      throw new Error(data?.message || data?.error || `Request failed (${response.status})`);
    }
    return data?.data ?? (data as any);
  }, [base]);

  const handleRegister = useCallback(async () => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const options = await callApi<any>('/webauthn/registration/options', {
        email: emailInput,
        identifier: emailInput,
      });
      const publicKey = transformOptions(options.publicKey ?? options);
      const credential = await navigator.credentials.create({ publicKey });
      if (!credential) throw new Error('Registration cancelled');
      const payload = credentialToJSON(credential as PublicKeyCredential);
      await callApi('/webauthn/registration/verify', { credential: payload, attemptId: options.attemptId });
      setMessage('Registration complete.');
    } catch (err: any) {
      setError(err?.message ?? 'Registration failed');
    } finally {
      setBusy(false);
    }
  }, [callApi, emailInput]);

  const handleLogin = useCallback(async () => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const options = await callApi<any>('/webauthn/authentication/options', {
        email: emailInput,
        identifier: emailInput,
      });
      const publicKey = transformOptions(options.publicKey ?? options);
      const credential = await navigator.credentials.get({ publicKey });
      if (!credential) throw new Error('Authentication cancelled');
      const payload = credentialToJSON(credential as PublicKeyCredential);
      await callApi('/webauthn/authentication/verify', { credential: payload, attemptId: options.attemptId });
      setMessage('Authentication successful.');
    } catch (err: any) {
      setError(err?.message ?? 'Authentication failed');
    } finally {
      setBusy(false);
    }
  }, [callApi, emailInput]);

  return (
    <section style={{ maxWidth: 420, padding: 16, border: '1px solid #e2e8f0', borderRadius: 8 }}>
      <h2>Passkey Login</h2>
      <label style={{ display: 'block', marginBottom: 12 }}>
        Email
        <input
          type="email"
          value={emailInput}
          onChange={(event) => setEmailInput(event.target.value)}
          style={{ width: '100%', padding: 8, marginTop: 4 }}
          placeholder="user@example.com"
        />
      </label>
      <div style={{ display: 'flex', gap: 12 }}>
        <button type="button" onClick={handleRegister} disabled={busy || !emailInput}>
          Register passkey
        </button>
        <button type="button" onClick={handleLogin} disabled={busy || !emailInput}>
          Login with passkey
        </button>
      </div>
      {busy && <p>Working…</p>}
      {message && <p style={{ color: '#16a34a' }}>{message}</p>}
      {error && <p style={{ color: '#dc2626' }}>{error}</p>}
    </section>
  );
}

export function ensureWebAuthnSupport() {
  if (!window.PublicKeyCredential) {
    throw new Error('WebAuthn is not supported in this browser');
  }
  return encoder;
}
