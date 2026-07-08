import prisma from "@flycockpit/db";
import { ORPCError } from "@orpc/server";
import { z } from "zod";

import { adminOr404Procedure } from "../index";

const mcpScopeSchema = z.enum(["read", "write"]);

export const apiKeysRouter = {
  setMcpScope: adminOr404Procedure
    .input(
      z.object({
        keyId: z.string().min(1),
        scope: mcpScopeSchema,
      }),
    )
    .handler(async ({ input, context }) => {
      const key = await prisma.apiKey.findUnique({
        where: { id: input.keyId },
        select: { id: true, userId: true, referenceId: true },
      });
      const ownerId = key?.userId ?? key?.referenceId;
      if (!key || ownerId !== context.session.user.id) {
        throw new ORPCError("NOT_FOUND", { message: "API key not found" });
      }

      await prisma.apiKey.update({
        where: { id: input.keyId },
        data: {
          permissions: JSON.stringify({
            mcp: input.scope === "write" ? ["read", "write"] : ["read"],
          }),
        },
      });

      return { success: true };
    }),
};
