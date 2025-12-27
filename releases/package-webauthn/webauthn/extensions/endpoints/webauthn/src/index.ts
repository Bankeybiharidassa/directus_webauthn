import { defineEndpoint, type ApiExtensionContext } from '@directus/extensions-sdk';
import type { Router } from 'express';
import { registerWebauthnRoutes, __testables, type WebAuthnConfig } from 'webauthn-router-shared';

export { __testables };
export type { WebAuthnConfig };

export default defineEndpoint((router: Router, context: ApiExtensionContext) => {
  const { logger, env: baseEnv, exceptions } = context as any;
  registerWebauthnRoutes(router, { context, baseEnv, logger, exceptions });
});
