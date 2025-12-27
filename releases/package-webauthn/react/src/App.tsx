import { useMemo } from 'react';
import { PasskeyLogin } from './PasskeyLogin';

export default function App() {
  const baseUrl = useMemo(() => {
    const value = import.meta.env.VITE_DIRECTUS_BASE_URL as string | undefined;
    if (!value) return '';
    return value.replace(/\/+$/, '');
  }, []);

  if (!baseUrl) {
    return (
      <main style={{ padding: 24 }}>
        <h1>WebAuthn Sample</h1>
        <p>Set <code>VITE_DIRECTUS_BASE_URL</code> to your Directus base URL.</p>
      </main>
    );
  }

  return (
    <main style={{ padding: 24 }}>
      <h1>WebAuthn Sample</h1>
      <PasskeyLogin
        baseUrl={baseUrl}
        email={import.meta.env.VITE_WEBAUTHN_EMAIL as string | undefined}
      />
    </main>
  );
}
