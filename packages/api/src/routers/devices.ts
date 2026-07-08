import prisma from "@flycockpit/db";
import { ORPCError } from "@orpc/server";
import { z } from "zod";

import { adminOr404Procedure } from "../index";

// Admin-facing readout of the better-auth `deviceCode` table. The
// device-authorization plugin only exposes per-flow endpoints (`/device/code`,
// `/device/approve`, etc.) and has no list/revoke API of its own — admins
// nonetheless need a way to see which devices they have approved and to
// invalidate one without waiting for the natural expiry. We scope every
// query to `session.user.id` so an admin can never see another admin's
// device codes.
export const devicesRouter = {
  list: adminOr404Procedure
    .input(
      z
        .object({
          limit: z.number().min(1).max(100).default(50),
        })
        .optional(),
    )
    .handler(async ({ input, context }) => {
      const limit = input?.limit ?? 50;
      const rows = await prisma.deviceCode.findMany({
        where: { userId: context.session.user.id },
        orderBy: { createdAt: "desc" },
        take: limit,
        select: {
          id: true,
          createdAt: true,
          expiresAt: true,
          status: true,
          userCode: true,
          clientId: true,
          scope: true,
          lastPolledAt: true,
        },
      });
      return rows;
    }),

  revoke: adminOr404Procedure
    .input(z.object({ id: z.string().min(1) }))
    .handler(async ({ input, context }) => {
      const row = await prisma.deviceCode.findUnique({ where: { id: input.id } });
      if (!row || row.userId !== context.session.user.id) {
        // Hide existence — same shape `adminOr404Procedure` would have used.
        throw new ORPCError("NOT_FOUND", { message: "Device code not found" });
      }
      await prisma.deviceCode.update({
        where: { id: input.id },
        data: { status: "denied" },
      });
      return { success: true };
    }),
};
