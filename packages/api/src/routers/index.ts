import prisma from "@flycockpit/db";
import { ADMIN_EMAILS, env, FORCE_SSO, SIGNUP_ENABLED, SSO_ENABLED } from "@flycockpit/env/server";
import type { RouterClient } from "@orpc/server";
import type { enterpriseRouter as EnterpriseRouter } from "../enterprise/router";
import { protectedProcedure, publicProcedure } from "../index";
import { apiKeysRouter } from "./api-keys";
import { assetsRouter } from "./assets";
import { authRouter } from "./auth";
import { consentRouter } from "./consent";
import { devicesRouter } from "./devices";
import { entitlementsRouter } from "./entitlements";
import { instanceSharingRouter } from "./instance-sharing";
import { instancesRouter } from "./instances";
import { maintenanceRouter } from "./maintenance";
import { notificationsRouter } from "./notifications";
import { pushRouter } from "./push";
import { queueRouter } from "./queue";
import { seedRouter } from "./seed";
import { settingsRouter } from "./settings";
import { usersRouter } from "./users";
import { videosRouter } from "./videos";

// Commercially licensed (see packages/api/src/enterprise/LICENSE) — loaded via
// profile-gated dynamic import so `oss` self-hosts never load or execute it.
// The static *type* is kept so clients stay fully typed; on oss deployments
// the procedures are absent at runtime and calls fail like any unknown path.
const enterpriseRouter: typeof EnterpriseRouter =
  env.DEPLOYMENT_PROFILE !== "oss"
    ? (await import("../enterprise/router")).enterpriseRouter
    : ({} as typeof EnterpriseRouter);

export const appRouter = {
  health: {
    check: publicProcedure.handler(() => {
      return "OK";
    }),
    ready: publicProcedure.handler(async () => {
      await prisma.$queryRaw`SELECT 1`;
      return "OK";
    }),
  },
  appConfig: publicProcedure.handler(() => {
    return {
      ssoEnabled: SSO_ENABLED,
      forceSso: FORCE_SSO,
      ssoProviderName: env.SSO_PROVIDER_NAME,
      signupEnabled: SIGNUP_ENABLED,
      adminBootstrapSignupEnabled: !SIGNUP_ENABLED && ADMIN_EMAILS.size > 0,
      // Gates the login challenge's "email me a code" affordance. The delivery
      // unreliability of Better-Auth's send-otp endpoint (it swallows SMTP
      // failures) is handled separately by the `auth.verifyEmailTransport`
      // preflight; this flag only reflects whether email is configured at all.
      emailEnabled: Boolean(env.SMTP_HOST),
    };
  }),
  privateData: protectedProcedure.handler(({ context }) => {
    return {
      message: "This is private",
      user: context.session?.user,
    };
  }),
  auth: authRouter,
  apiKeys: apiKeysRouter,
  settings: settingsRouter,
  push: pushRouter,
  queue: queueRouter,
  seed: seedRouter,
  assets: assetsRouter,
  consent: consentRouter,
  devices: devicesRouter,
  enterprise: enterpriseRouter,
  entitlements: entitlementsRouter,
  instances: instancesRouter,
  instanceSharing: instanceSharingRouter,
  maintenance: maintenanceRouter,
  notifications: notificationsRouter,
  users: usersRouter,
  videos: videosRouter,
};
export type AppRouter = typeof appRouter;
export type AppRouterClient = RouterClient<typeof appRouter>;
