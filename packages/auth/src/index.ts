import { apiKey } from "@better-auth/api-key";
import prisma from "@flycockpit/db";
import { ADMIN_EMAILS, env, FORCE_SSO, SIGNUP_ENABLED, SSO_ENABLED } from "@flycockpit/env/server";
import { renderTwoFactorOtp, renderVerifyEmail, sendEmail } from "@flycockpit/mailer";
import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { admin, deviceAuthorization, genericOAuth, twoFactor } from "better-auth/plugins";
import { getAllowedUserCreationMode } from "./user-creation-policy.js";

const ssoEnabled = SSO_ENABLED;
const forceSso = FORCE_SSO;
const isCrossOrigin = !!env.CORS_ORIGIN;

// Better-Auth emits "user input failed validation" cases (wrong password, unknown
// email, unverified email, etc.) at level=error. Those are normal end-user mistakes,
// not server faults — downgrade them to warn so production error dashboards stay
// signal-y. Anything we don't recognize keeps its original level.
const USER_INPUT_ERROR_PATTERN =
  /invalid (password|email|credentials|token|otp|two[- ]?factor)|user not found|email not verified|password is incorrect|account not found|failed to verify|already exists|too many (requests|attempts)/i;

export const auth = betterAuth({
  database: prismaAdapter(prisma, {
    provider: "postgresql",
  }),

  logger: {
    log(level, message, ...args) {
      const effective =
        level === "error" && USER_INPUT_ERROR_PATTERN.test(message) ? "warn" : level;
      if (effective === "error") console.error(`[auth] ${message}`, ...args);
      else if (effective === "warn") console.warn(`[auth] ${message}`, ...args);
      else if (effective === "info") console.info(`[auth] ${message}`, ...args);
    },
  },

  trustedOrigins: isCrossOrigin ? [env.CORS_ORIGIN!, env.BETTER_AUTH_URL] : [env.BETTER_AUTH_URL],
  user: {
    additionalFields: {
      // Surface the Prisma `User.locale` column on the typed session so the
      // web app can read `session.user.locale` (and the i18n hook can sync it
      // into i18next). Default mirrors the Prisma `@default("en-US")` so a
      // pre-existing user that hasn't picked a locale yet reads as en-US.
      locale: {
        type: "string",
        required: false,
        defaultValue: "en-US",
        input: false, // not settable via signUp/updateUser; goes through the dedicated procedure
      },
      operationalAlerts: {
        type: "boolean",
        required: false,
        defaultValue: true,
        input: false,
      },
    },
  },
  emailAndPassword: {
    enabled: !forceSso,
    requireEmailVerification: true,
    minPasswordLength: 12,
  },
  emailVerification: {
    sendVerificationEmail: async ({ user, url }) => {
      // Better-Auth's `additionalFields` are present at runtime but the
      // sendVerificationEmail callback's `user` is typed against the base
      // user shape — `locale` isn't on it. Fetch the row via Prisma so the
      // recipient's preferred locale routes through to the renderer (which
      // falls back to en-US for any unsupported / missing value).
      const row = await prisma.user.findUnique({
        where: { id: user.id },
        select: { locale: true },
      });
      const { subject, html } = renderVerifyEmail({
        url,
        locale: row?.locale ?? "en-US",
      });
      await sendEmail({
        to: user.email,
        subject,
        html,
      });
    },
    sendOnSignUp: true,
  },
  secret: env.BETTER_AUTH_SECRET,
  baseURL: env.BETTER_AUTH_URL,
  session: {
    // session:30d, refresh every 1d
    expiresIn: 60 * 60 * 24 * 30,
    updateAge: 60 * 60 * 24,
    cookieCache: {
      enabled: true,
      maxAge: 60,
    },
  },
  advanced: {
    defaultCookieAttributes: isCrossOrigin
      ? { sameSite: "none", secure: true, httpOnly: true }
      : { httpOnly: true, secure: env.NODE_ENV === "production" },
  },
  plugins: [
    admin({
      defaultRole: "user",
    }),
    twoFactor({
      issuer: "Flycockpit",
      // Email OTP as a second factor — only wired when SMTP is configured.
      // TOTP + backup codes always remain available regardless.
      //
      // Caveat (documented, mitigated elsewhere): Better-Auth's send-otp
      // endpoint catches a thrown/rejected sendOTP and still returns
      // { status: true } (otp/index.ts) — it will NOT surface an SMTP failure to
      // the caller. The login challenge therefore preflights SMTP reachability
      // via `auth.verifyEmailTransport` (→ mailer `verifyTransport()`) before
      // claiming a code was sent. Here we just do the real send and let a
      // failure throw so it is logged server-side.
      ...(env.SMTP_HOST
        ? {
            otpOptions: {
              // Hash codes at rest rather than storing them in plaintext
              // (Better-Auth's default).
              storeOTP: "hashed" as const,
              sendOTP: async ({
                user,
                otp,
              }: {
                user: { id: string; email: string };
                otp: string;
              }) => {
                // additionalFields like `locale` aren't on the callback's typed
                // user shape — fetch the row so the code email is localized
                // (renderer falls back to en-US for missing/unsupported values).
                const row = await prisma.user.findUnique({
                  where: { id: user.id },
                  select: { locale: true },
                });
                const { subject, html } = renderTwoFactorOtp({
                  otp,
                  locale: row?.locale ?? "en-US",
                });
                await sendEmail({ to: user.email, subject, html });
              },
            },
          }
        : {}),
    }),
    // Scoped admin API keys. Read from the `Authorization: Bearer <token>`
    // header so MCP clients (Claude Desktop / Claude Code) can paste the key
    // straight into their `headers.Authorization`. Names are required so the
    // /admin/api-keys list never shows "Untitled". `enableSessionForAPIKeys`
    // mocks a session for the owner whenever the key is present, which the
    // MCP middleware relies on to share `auth.api.getSession` between API-key
    // and OAuth-token callers.
    apiKey(
      {
        apiKeyHeaders: "authorization",
        requireName: true,
        enableMetadata: true,
        enableSessionForAPIKeys: true,
        customAPIKeyGetter: (ctx) => {
          const h = ctx.headers?.get("authorization");
          return h?.startsWith("Bearer ") ? h.slice(7) : null;
        },
      },
      {
        // The Prisma client exposes our table as `prisma.apiKey` (camelCased
        // from `model ApiKey`), but better-auth's adapter looks up the lower-
        // cased plugin model name (`apikey`). Tell the adapter the JS model
        // accessor is `apiKey` so it doesn't 500 on every request.
        schema: { apikey: { modelName: "apiKey" } },
      },
    ),
    // OAuth 2.0 Device Authorization Grant (RFC 8628). Lets MCP clients that
    // can't paste a static token (e.g. desktop apps that use a browser-based
    // login flow) bootstrap an admin session via /device. We do not enable
    // `oauthProvider` here — device flow alone is enough for MVP. See
    // the MCP OAuth upgrade notes for the full OAuth code-flow upgrade path.
    // The plugin's options schema uses `z.custom(() => true)` for the
    // `schema` field without `.optional()`, so we have to pass it explicitly
    // (even as `undefined`) or zod rejects the call at startup.
    deviceAuthorization({
      expiresIn: "30m",
      interval: "5s",
      // Same Prisma camelCase ↔ better-auth lowercase mismatch as apiKey: the
      // adapter looks up `db.deviceCode` by the schema key `deviceCode`, but
      // we still need to pass the field through so the options-schema parser
      // (which marks `schema` as nonoptional) doesn't reject the call.
      schema: { deviceCode: { modelName: "deviceCode" } },
    }),
    ...(ssoEnabled && env.SSO_CLIENT_ID && env.SSO_CLIENT_SECRET && env.SSO_ISSUER
      ? [
          genericOAuth({
            config: [
              {
                providerId: "sso",
                discoveryUrl: `${env.SSO_ISSUER}/.well-known/openid-configuration`,
                clientId: env.SSO_CLIENT_ID,
                clientSecret: env.SSO_CLIENT_SECRET,
                scopes: ["openid", "profile", "email"],
              },
            ],
          }),
        ]
      : []),
  ],
  databaseHooks: {
    user: {
      create: {
        before: async (user) => {
          const email = user.email?.toLowerCase();
          const creationMode = getAllowedUserCreationMode();
          if (!SIGNUP_ENABLED && !creationMode) {
            throw new Error("Sign-up is currently disabled. Contact an admin if you need access.");
          }
          // ADMIN_EMAILS promotion is only for the explicit email/password
          // bootstrap path wrapped by the server signup guard. Never infer it
          // from SSO/JIT user creation or from emailVerified claims.
          if (creationMode === "admin-bootstrap" && email && ADMIN_EMAILS.has(email)) {
            return {
              data: {
                ...user,
                role: "admin",
              },
            };
          }
          return { data: user };
        },
      },
    },
  },
});

export type Session = typeof auth.$Infer.Session;
