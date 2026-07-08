import prisma from "@flycockpit/db";
import { ADMIN_EMAILS } from "@flycockpit/env/server";
import { ORPCError } from "@orpc/server";
import { z } from "zod";

import { adminOr404Procedure, authenticatedProcedure } from "../index";
import { FORCE_2FA_SETTING_KEYS, READABLE_FORCE_2FA_SETTING_KEYS } from "../lib/two-factor-policy";

// Leak-prevention boundary: only keys listed here are exposed to clients via getAll; future settings must be explicitly opted in.
const CLIENT_READABLE_SETTING_KEYS: readonly string[] = READABLE_FORCE_2FA_SETTING_KEYS;
const writableSettingKeySchema = z.enum(FORCE_2FA_SETTING_KEYS);

export const settingsRouter = {
  getAll: authenticatedProcedure.handler(async () => {
    const settings = await prisma.appSetting.findMany({
      where: { key: { in: [...CLIENT_READABLE_SETTING_KEYS] } },
    });
    return Object.fromEntries(settings.map((s) => [s.key, s.value]));
  }),

  /**
   * Returns admin-setup status so the client can render a prominent warning
   * banner when ADMIN_EMAILS is empty (no users will ever be granted admin
   * privileges). Authenticated so the banner only shows to logged-in users.
   */
  adminSetupStatus: authenticatedProcedure.handler(() => {
    return {
      adminEmailsEmpty: ADMIN_EMAILS.size === 0,
    };
  }),

  myNotificationPreferences: authenticatedProcedure.handler(async ({ context }) => {
    const user = await prisma.user.findUnique({
      where: { id: context.session.user.id },
      select: { operationalAlerts: true },
    });
    return {
      operationalAlerts: user?.operationalAlerts ?? true,
    };
  }),

  updateMyNotificationPreferences: authenticatedProcedure
    .input(
      z.object({
        operationalAlerts: z.boolean(),
      }),
    )
    .handler(async ({ input, context }) => {
      await prisma.user.update({
        where: { id: context.session.user.id },
        data: { operationalAlerts: input.operationalAlerts },
      });
      return { success: true };
    }),

  myTerminalSecurityPreferences: authenticatedProcedure.handler(async ({ context }) => {
    const user = await prisma.user.findUnique({
      where: { id: context.session.user.id },
      select: { terminalStepUpRelaxed: true },
    });
    return { terminalStepUpRelaxed: user?.terminalStepUpRelaxed ?? false };
  }),

  updateMyTerminalSecurityPreferences: authenticatedProcedure
    .input(z.object({ terminalStepUpRelaxed: z.boolean() }))
    .handler(async ({ input, context }) => {
      await prisma.user.update({
        where: { id: context.session.user.id },
        data: { terminalStepUpRelaxed: input.terminalStepUpRelaxed },
      });
      return { success: true };
    }),

  update: adminOr404Procedure
    .input(
      z.object({
        key: writableSettingKeySchema,
        value: z.enum(["true", "false"]),
      }),
    )
    .handler(async ({ input, context }) => {
      // Strict by design: an admin must secure their own account before
      // requiring 2FA for either public users or internal/admin users.
      if (input.value === "true") {
        if (!context.session.user.twoFactorEnabled) {
          throw new ORPCError("FORBIDDEN", {
            message: "You must enable 2FA for your own account before requiring it for others",
          });
        }
      }

      await prisma.appSetting.upsert({
        where: { key: input.key },
        update: { value: input.value },
        create: { key: input.key, value: input.value },
      });

      return { success: true };
    }),
};
