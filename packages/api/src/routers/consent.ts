import prisma from "@flycockpit/db";
import { z } from "zod";

import { adminOr404Procedure, publicProcedure } from "../index";

/**
 * Consent proof-of-record. The cookie on the client is the source of truth
 * for *gating*; this router only writes an append-only server log for GDPR
 * accountability (Art. 5(2) / 7(1)).
 *
 * `record` is intentionally `publicProcedure` — consent is given before any
 * login, so the visitor is usually anonymous. The signed-in user id (if any)
 * is taken from the session, never from client input. The write is
 * best-effort: the client fires it and ignores the result, so a failure here
 * never blocks the UI or the gating decision.
 */

const categoriesSchema = z.object({
  functional: z.boolean(),
  analytics: z.boolean(),
  marketing: z.boolean(),
});

// The API boundary (both `record` input and `recentRecords` output) speaks the
// lowercase snake_case vocabulary the client/cookie use; the Prisma enum members
// are SCREAMING_CASE per Prisma convention. Map at both edges so callers never
// see the enum spelling. `@map` keeps the DB column values lowercase too.
const consentActionToDb = {
  accept_all: "ACCEPT_ALL",
  reject_all: "REJECT_ALL",
  custom: "CUSTOM",
} as const;

const consentActionFromDb = {
  ACCEPT_ALL: "accept_all",
  REJECT_ALL: "reject_all",
  CUSTOM: "custom",
} as const;

export const consentRouter = {
  record: publicProcedure
    .input(
      z.object({
        anonId: z.string().min(1).max(64),
        policyVersion: z.number().int().min(0).max(1_000_000),
        categories: categoriesSchema,
        action: z.enum(["accept_all", "reject_all", "custom"]),
        userAgent: z.string().max(512).optional(),
      }),
    )
    .handler(async ({ input, context }) => {
      await prisma.consentRecord.create({
        data: {
          anonId: input.anonId,
          userId: context.session?.user?.id ?? null,
          policyVersion: input.policyVersion,
          categories: input.categories,
          action: consentActionToDb[input.action],
          userAgent: input.userAgent ?? null,
        },
      });
      return { success: true };
    }),

  /**
   * Paginated, newest-first export for compliance. `adminOr404Procedure` so a
   * non-admin can't even probe that the consent log exists (mirrors the
   * 404-hidden admin surfaces).
   */
  recentRecords: adminOr404Procedure
    .input(
      z.object({
        anonId: z.string().max(64).optional(),
        userId: z.string().max(191).optional(),
        cursor: z.string().optional(),
        limit: z.number().int().min(1).max(100).default(50),
      }),
    )
    .handler(async ({ input }) => {
      const items = await prisma.consentRecord.findMany({
        where: { anonId: input.anonId, userId: input.userId },
        take: input.limit + 1,
        ...(input.cursor && { cursor: { id: input.cursor }, skip: 1 }),
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        include: { user: { select: { id: true, name: true, email: true } } },
      });

      let nextCursor: string | undefined;
      if (items.length > input.limit) {
        nextCursor = items.pop()?.id;
      }
      return {
        items: items.map((item) => ({ ...item, action: consentActionFromDb[item.action] })),
        nextCursor,
      };
    }),
};
