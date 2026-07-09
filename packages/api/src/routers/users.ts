import { randomBytes } from "node:crypto";
import { auth } from "@flycockpit/auth";
import { runWithAllowedUserCreation } from "@flycockpit/auth/user-creation-policy";
import prisma from "@flycockpit/db";
import { env } from "@flycockpit/env/server";
import { renderInviteUser, sendEmail } from "@flycockpit/mailer";
import { ORPCError } from "@orpc/server";
import { z } from "zod";

import { adminOr404Procedure } from "../index";
import { revokeInstanceAccessGrantsForDeletedUser } from "../lib/instance-sharing";

// Roles surfaced in the admin UI. Better-auth itself stores `role` as a free-
// form string (and supports comma-separated lists), but the admin dashboard
// only ever assigns one of these two — anything else came from custom code or
// a database edit and we leave it untouched.
const ASSIGNABLE_ROLES = ["user", "admin"] as const;
const ASSIGNABLE_PLANS = ["FREE", "PRO"] as const;
const assignableRoleSchema = z.enum(ASSIGNABLE_ROLES);
const assignablePlanSchema = z.enum(ASSIGNABLE_PLANS);

const userIdInput = z.object({ userId: z.string().min(1) });

function generateTempPassword(): string {
  // 24 url-safe bytes → ~32 chars. Long enough to satisfy any reasonable
  // strength check; short enough to read from an email.
  return randomBytes(24).toString("base64url");
}

const USER_SELECT = {
  id: true,
  email: true,
  name: true,
  role: true,
  emailVerified: true,
  banned: true,
  banReason: true,
  banExpires: true,
  twoFactorEnabled: true,
  plan: true,
  hostedTrialEndsAt: true,
  image: true,
  createdAt: true,
  updatedAt: true,
} as const;

export const usersRouter = {
  list: adminOr404Procedure
    .input(
      z
        .object({
          limit: z.number().min(1).max(200).default(50),
          offset: z.number().min(0).default(0),
          search: z.string().trim().max(200).optional(),
        })
        .optional(),
    )
    .handler(async ({ input }) => {
      const limit = input?.limit ?? 50;
      const offset = input?.offset ?? 0;
      const search = input?.search;
      const where = search
        ? {
            OR: [
              { email: { contains: search, mode: "insensitive" as const } },
              { name: { contains: search, mode: "insensitive" as const } },
            ],
          }
        : {};
      const [users, total] = await Promise.all([
        prisma.user.findMany({
          where,
          orderBy: { createdAt: "desc" },
          take: limit,
          skip: offset,
          select: USER_SELECT,
        }),
        prisma.user.count({ where }),
      ]);
      return { users, total, limit, offset };
    }),

  invite: adminOr404Procedure
    .input(
      z.object({
        email: z.string().email().toLowerCase(),
        name: z.string().trim().min(1).max(100),
        role: assignableRoleSchema.default("user"),
      }),
    )
    .handler(async ({ input }) => {
      const tempPassword = generateTempPassword();

      // `auth.api.createUser` is the only admin-plugin endpoint that accepts
      // server-side calls without a session in headers (verified in the
      // better-auth source). It hashes the password, enforces email
      // uniqueness, and writes through the Prisma adapter so it stays in
      // sync with any custom databaseHooks (e.g. ADMIN_EMAILS auto-promote).
      let userId: string;
      let recipientLocale: string;
      try {
        const created = await runWithAllowedUserCreation("admin-invite", () =>
          auth.api.createUser({
            body: {
              email: input.email,
              password: tempPassword,
              name: input.name,
              role: input.role,
            },
          }),
        );
        userId = created.user.id;
        // The User row was just created with the Prisma `@default("en-US")`
        // for `locale`. Read it back so a future change to the default (or a
        // hook that overrides it) flows through to the email render without
        // additional plumbing here.
        const fresh = await prisma.user.findUnique({
          where: { id: userId },
          select: { locale: true },
        });
        recipientLocale = fresh?.locale ?? "en-US";
      } catch (err) {
        const message = err instanceof Error ? err.message : "Failed to invite user";
        if (/already exists|already in use|duplicate/i.test(message)) {
          throw new ORPCError("CONFLICT", {
            message: "A user with that email already exists.",
          });
        }
        if (/sign-?up.*disabled|disabled.*sign-?up/i.test(message)) {
          throw new ORPCError("BAD_REQUEST", {
            message:
              "Account creation is disabled by the auth configuration. Ask an admin to check the invite setup.",
          });
        }
        // Log only name+message — the generated temp password was just
        // passed to auth.api.createUser, so we don't dump the raw error
        // object in case a future better-auth release attaches request
        // context to thrown errors.
        const errLabel = err instanceof Error ? `${err.name}: ${err.message}` : "unknown error";
        console.error("[users.invite] auth.api.createUser failed:", errLabel);
        throw new ORPCError("INTERNAL_SERVER_ERROR", {
          message:
            "Couldn't create that account. Try again, or contact an admin if it keeps happening.",
        });
      }

      // Email send is best-effort: if SMTP is not configured (or fails) we
      // still return the temp password to the admin so they can share it
      // out of band. The email failure is logged but does not roll back the
      // user creation — undoing it would race against any concurrent admin
      // who is already looking at the new row.
      let emailSent = false;
      try {
        const { subject, html } = renderInviteUser({
          name: input.name,
          email: input.email,
          tempPassword,
          signInUrl: `${env.BETTER_AUTH_URL}/login`,
          locale: recipientLocale,
        });
        await sendEmail({ to: input.email, subject, html });
        emailSent = true;
      } catch (err) {
        console.warn("[users.invite] failed to send invite email", err);
      }

      return { userId, tempPassword, emailSent };
    }),

  setPlan: adminOr404Procedure
    .input(
      z.object({
        userId: z.string().min(1),
        plan: assignablePlanSchema,
      }),
    )
    .handler(async ({ input }) => {
      const target = await prisma.user.findUnique({
        where: { id: input.userId },
        select: { id: true },
      });
      if (!target) throw new ORPCError("NOT_FOUND", { message: "User not found" });

      await prisma.user.update({
        where: { id: input.userId },
        data: { plan: input.plan },
      });
      return { success: true };
    }),

  setRole: adminOr404Procedure
    .input(
      z.object({
        userId: z.string().min(1),
        role: assignableRoleSchema,
      }),
    )
    .handler(async ({ input, context }) => {
      // Don't let an admin demote themselves — if they're the only admin
      // they'd lock themselves (and everyone) out of /admin.
      if (input.userId === context.session.user.id && input.role !== "admin") {
        throw new ORPCError("FORBIDDEN", {
          message: "You cannot remove your own admin role.",
        });
      }
      const target = await prisma.user.findUnique({
        where: { id: input.userId },
        select: { id: true },
      });
      if (!target) throw new ORPCError("NOT_FOUND", { message: "User not found" });

      await prisma.user.update({
        where: { id: input.userId },
        data: { role: input.role },
      });
      return { success: true };
    }),

  archive: adminOr404Procedure
    .input(
      z.object({
        userId: z.string().min(1),
        reason: z.string().trim().max(500).optional(),
      }),
    )
    .handler(async ({ input, context }) => {
      if (input.userId === context.session.user.id) {
        throw new ORPCError("FORBIDDEN", {
          message: "You cannot archive your own account.",
        });
      }
      const target = await prisma.user.findUnique({
        where: { id: input.userId },
        select: { id: true },
      });
      if (!target) throw new ORPCError("NOT_FOUND", { message: "User not found" });

      // Set banned=true so better-auth treats the user as locked, and revoke
      // every active session so the next page-load signs them out. We mirror
      // what the admin plugin's banUser endpoint does internally — no expiry
      // (banExpires=null), no auto-unban.
      await prisma.$transaction([
        prisma.user.update({
          where: { id: input.userId },
          data: {
            banned: true,
            banReason: input.reason ?? null,
            banExpires: null,
          },
        }),
        prisma.session.deleteMany({ where: { userId: input.userId } }),
      ]);
      return { success: true };
    }),

  unarchive: adminOr404Procedure.input(userIdInput).handler(async ({ input }) => {
    const target = await prisma.user.findUnique({
      where: { id: input.userId },
      select: { id: true },
    });
    if (!target) throw new ORPCError("NOT_FOUND", { message: "User not found" });

    await prisma.user.update({
      where: { id: input.userId },
      data: { banned: false, banReason: null, banExpires: null },
    });
    return { success: true };
  }),

  remove: adminOr404Procedure.input(userIdInput).handler(async ({ input, context }) => {
    if (input.userId === context.session.user.id) {
      throw new ORPCError("FORBIDDEN", {
        message: "You cannot delete your own account.",
      });
    }
    const target = await prisma.user.findUnique({
      where: { id: input.userId },
      select: { id: true },
    });
    if (!target) throw new ORPCError("NOT_FOUND", { message: "User not found" });

    // Sessions, accounts, two-factors, api keys, device codes and push subs
    // cascade. Any remaining restricted relation produces a Prisma constraint
    // error, which we surface as archive guidance instead.
    try {
      await revokeInstanceAccessGrantsForDeletedUser({
        userId: input.userId,
        actorUserId: context.session.user.id,
      });
      await prisma.user.delete({ where: { id: input.userId } });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to delete user";
      if (/foreign key|constraint|restrict/i.test(message)) {
        throw new ORPCError("CONFLICT", {
          message:
            "This user still has related records and cannot be deleted. Archive them instead, or reassign the records first.",
        });
      }
      console.error("[users.remove] prisma delete failed", err);
      throw new ORPCError("INTERNAL_SERVER_ERROR", {
        message:
          "Couldn't delete that account. Try again, or contact an admin if it keeps happening.",
      });
    }
    return { success: true };
  }),
};
