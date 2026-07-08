import { SUPPORTED_LOCALES } from "@flycockpit/config/locales";
import prisma from "@flycockpit/db";
import { verifyTransport } from "@flycockpit/mailer";
import { z } from "zod";

import { protectedProcedure, publicProcedure } from "../index";

export const authRouter = {
  /**
   * Delivery-aware preflight for the email-OTP second factor. The login
   * challenge calls this BEFORE `authClient.twoFactor.sendOtp()` because
   * Better-Auth's send-otp endpoint swallows `sendOTP` failures and always
   * returns success — so without this check a user could be told "code sent"
   * when SMTP is unreachable.
   *
   * Public: the caller is mid-2FA (password verified, but no full session yet),
   * so a protected procedure can't be used. It's rate-limited via the shared
   * `/rpc` limiter and only triggers a handshake against the app's OWN
   * configured SMTP host. Returns `{ ok }` rather than throwing so the client
   * can branch cleanly.
   */
  verifyEmailTransport: publicProcedure.handler(async () => {
    return { ok: await verifyTransport() };
  }),
  /**
   * Persist the signed-in user's preferred UI locale. Called silently from
   * the LanguageSwitcher when an authenticated user picks a language so the
   * choice follows them across devices.
   *
   * Authenticated only. The session-derived `user.locale` is consumed by
   * `useUserLocaleSync()` on the next session refresh.
   */
  updateLocale: protectedProcedure
    .input(z.object({ locale: z.enum(SUPPORTED_LOCALES) }))
    .handler(async ({ input, context }) => {
      await prisma.user.update({
        where: { id: context.session.user.id },
        data: { locale: input.locale },
      });
      return { success: true };
    }),
};
