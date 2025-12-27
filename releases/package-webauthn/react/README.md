# React WebAuthn Sample

This folder contains sample React code that integrates with the WebAuthn endpoints exposed by the Directus extension.

## Files

- `src/PasskeyLogin.tsx` – helper component for register + authenticate.
- `src/App.tsx` – example usage of the component.
- `src/main.tsx` – minimal entry point.
- `package.json` – dependency list for local testing.

## Environment variables

Set these variables in your runtime (do not hardcode URLs in source):

- `VITE_DIRECTUS_BASE_URL` – base URL for the Directus instance.
- `VITE_WEBAUTHN_EMAIL` – optional email prefill for login.

## Usage

Integrate `PasskeyLogin` into your app and supply the base URL:

```tsx
<PasskeyLogin baseUrl={import.meta.env.VITE_DIRECTUS_BASE_URL} />
```
