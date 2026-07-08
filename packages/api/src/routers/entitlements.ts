import { ORPCError } from "@orpc/server";
import { z } from "zod";
import { protectedProcedure, publicProcedure } from "../index";
import { getPublicDeploymentProfile } from "../lib/deployment-profile";
import { getUserEntitlements } from "../lib/entitlements";

const capabilitySchema = z.enum([
  "nativeAppAccess",
  "ownedInstanceConnections",
  "sharingEnabled",
  "logExport",
]);

export const entitlementsRouter = {
  deploymentProfile: publicProcedure.handler(() => getPublicDeploymentProfile()),

  mine: protectedProcedure.handler(async ({ context }) => {
    return getUserEntitlements(context.session.user.id);
  }),

  can: protectedProcedure
    .input(z.object({ capability: capabilitySchema }))
    .handler(async ({ input, context }) => {
      const entitlements = await getUserEntitlements(context.session.user.id);
      const allowed = entitlements[input.capability];
      if (typeof allowed !== "boolean") throw new ORPCError("BAD_REQUEST");
      return { allowed };
    }),
};
