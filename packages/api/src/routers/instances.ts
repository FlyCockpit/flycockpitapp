import prisma from "@flycockpit/db";
import { env } from "@flycockpit/env/server";
import { ORPCError } from "@orpc/server";
import { z } from "zod";
import { authenticatedProcedure, protectedProcedure, publicProcedure } from "../index";
import { limit } from "../lib/entitlements";
import {
  createInstanceCredential,
  parseInstanceToken,
  verifyInstanceSecret,
} from "../lib/instance-credentials";
import {
  activeSharedRelayGrantsForUser,
  ownerAgentGrants,
  ownerTerminalGrant,
  requireActiveInstanceForAccess,
} from "../lib/instance-sharing";
import { createRelayToken } from "../lib/relay-tokens";
import { requireConfiguredRelayForMint } from "../lib/relay-url";

const TERMINAL_STEP_UP_GRACE_MS = 5 * 60 * 1000;

const instanceRegisterInput = z.object({
  hostname: z.string().trim().min(1).max(255),
  os: z.string().trim().min(1).max(120),
  arch: z.string().trim().min(1).max(80),
  cliVersion: z.string().trim().min(1).max(80),
  displayName: z.string().trim().min(1).max(120).optional(),
  instanceId: z.string().min(1).optional(),
});

const displayNameInput = z.object({
  instanceId: z.string().min(1),
  displayName: z.string().trim().min(1).max(120),
});

const instanceTokenInput = z.object({
  instanceId: z.string().min(1),
  instanceToken: z.string().min(1),
});

const connectorTokenInput = instanceTokenInput.extend({
  relayId: z.string().min(1),
});

const userCodeInput = z.object({
  userCode: z.string().trim().min(1).max(64),
});
function serializeInstance(instance: {
  id: string;
  displayName: string;
  hostname: string;
  os: string;
  arch: string;
  cliVersion: string;
  status: unknown;
  createdAt: Date;
  updatedAt: Date;
  lastSeenAt: Date | null;
  revokedAt: Date | null;
}) {
  return {
    id: instance.id,
    displayName: instance.displayName,
    hostname: instance.hostname,
    os: instance.os,
    arch: instance.arch,
    cliVersion: instance.cliVersion,
    status: String(instance.status),
    createdAt: instance.createdAt,
    updatedAt: instance.updatedAt,
    lastSeenAt: instance.lastSeenAt,
    revokedAt: instance.revokedAt,
    presence: instance.revokedAt
      ? "revoked"
      : isRecentlySeen(instance.lastSeenAt)
        ? "online"
        : "offline",
  };
}

function isRecentlySeen(lastSeenAt: Date | null) {
  if (!lastSeenAt) return false;
  return Date.now() - lastSeenAt.getTime() < 45_000;
}

async function findInstanceForToken(instanceId: string, instanceToken: string) {
  const parsed = parseInstanceToken(instanceToken);
  if (!parsed) throw new ORPCError("UNAUTHORIZED", { message: "Invalid instance token." });

  const instance = await prisma.cockpitInstance.findUnique({ where: { id: instanceId } });
  if (!instance || instance.secretPrefix !== parsed.prefix) {
    throw new ORPCError("UNAUTHORIZED", { message: "Invalid instance token." });
  }
  if (String(instance.status) !== "ACTIVE" || instance.revokedAt) {
    throw new ORPCError("FORBIDDEN", { message: "This instance has been revoked." });
  }
  if (!verifyInstanceSecret(parsed.secret, instance.secretHash)) {
    throw new ORPCError("UNAUTHORIZED", { message: "Invalid instance token." });
  }
  return instance;
}

function hasRecentStepUp(sessionCreatedAt: Date) {
  return Date.now() - sessionCreatedAt.getTime() <= TERMINAL_STEP_UP_GRACE_MS;
}

function terminalStepUpExpiresAt(sessionCreatedAt: Date) {
  return new Date(sessionCreatedAt.getTime() + TERMINAL_STEP_UP_GRACE_MS);
}

type RelayMintTarget = { relayId: string; relayUrl: string };

function ossRelayTarget(): RelayMintTarget {
  const target = requireConfiguredRelayForMint();
  return { relayId: target.relayId, relayUrl: target.relayUrl };
}

async function resolveConnectorRelayTarget(
  relayId: string,
  instanceId: string,
): Promise<RelayMintTarget> {
  if (env.DEPLOYMENT_PROFILE === "oss") {
    const target = ossRelayTarget();
    if (target.relayId !== relayId) {
      throw new ORPCError("NOT_FOUND", { message: "Relay not found." });
    }
    return target;
  }

  const { recordConnectorRelayLease } = await import("../enterprise/relay-fleet");
  const target = await recordConnectorRelayLease(relayId, instanceId);
  return { relayId: target.relayId, relayUrl: target.wsUrl };
}

async function resolveClientRelayTarget(instanceId: string): Promise<RelayMintTarget> {
  if (env.DEPLOYMENT_PROFILE === "oss") return ossRelayTarget();

  const { resolveRelayForInstance } = await import("../enterprise/relay-fleet");
  const target = await resolveRelayForInstance(instanceId);
  return { relayId: target.relayId, relayUrl: target.wsUrl };
}

async function relayCandidatesForInstance() {
  if (env.DEPLOYMENT_PROFILE === "oss") {
    const target = ossRelayTarget();
    return [{ relayId: target.relayId, region: null, wsUrl: target.relayUrl }];
  }

  const { listRelayCandidates } = await import("../enterprise/relay-fleet");
  return listRelayCandidates();
}

async function requireOwnedActiveInstance(instanceId: string, userId: string) {
  const instance = await prisma.cockpitInstance.findUnique({ where: { id: instanceId } });
  if (!instance || instance.userId !== userId) {
    throw new ORPCError("NOT_FOUND", { message: "Instance not found." });
  }
  if (String(instance.status) !== "ACTIVE" || instance.revokedAt) {
    throw new ORPCError("FORBIDDEN", { message: "This instance has been revoked." });
  }
  return instance;
}

export const instancesRouter = {
  listMine: protectedProcedure.handler(async ({ context }) => {
    const instances = await prisma.cockpitInstance.findMany({
      where: { userId: context.session.user.id },
      orderBy: [{ revokedAt: "asc" }, { lastSeenAt: "desc" }, { createdAt: "desc" }],
    });
    return { instances: instances.map(serializeInstance) };
  }),

  lookupDeviceCode: authenticatedProcedure.input(userCodeInput).handler(async ({ input }) => {
    const deviceCode = await prisma.deviceCode.findUnique({
      where: { userCode: input.userCode },
      select: { userCode: true, status: true, clientId: true, scope: true, expiresAt: true },
    });
    if (!deviceCode) throw new ORPCError("NOT_FOUND", { message: "Device code not found." });
    return deviceCode;
  }),

  register: protectedProcedure.input(instanceRegisterInput).handler(async ({ input, context }) => {
    const userId = context.session.user.id;
    const displayName = input.displayName?.trim() || input.hostname;
    const credential = createInstanceCredential();

    const existing = input.instanceId
      ? await prisma.cockpitInstance.findFirst({
          where: { id: input.instanceId, userId, status: "ACTIVE", revokedAt: null },
        })
      : null;

    if (existing) {
      const instance = await prisma.cockpitInstance.update({
        where: { id: existing.id },
        data: {
          displayName,
          hostname: input.hostname,
          os: input.os,
          arch: input.arch,
          cliVersion: input.cliVersion,
          secretPrefix: credential.prefix,
          secretHash: credential.hash,
          lastSeenAt: new Date(),
        },
      });
      return {
        instanceId: instance.id,
        instanceToken: credential.token,
        account: { userId, email: context.session.user.email },
      };
    }

    const maxInstances = await limit(userId, "instances");
    const activeCount = await prisma.cockpitInstance.count({
      where: { userId, status: "ACTIVE", revokedAt: null },
    });
    if (activeCount >= maxInstances) {
      throw new ORPCError("FORBIDDEN", {
        message:
          "Instance limit reached (" +
          maxInstances +
          "). Revoke an old instance before adding another.",
      });
    }

    const instance = await prisma.cockpitInstance.create({
      data: {
        userId,
        displayName,
        hostname: input.hostname,
        os: input.os,
        arch: input.arch,
        cliVersion: input.cliVersion,
        secretPrefix: credential.prefix,
        secretHash: credential.hash,
        lastSeenAt: new Date(),
      },
    });

    return {
      instanceId: instance.id,
      instanceToken: credential.token,
      account: { userId, email: context.session.user.email },
    };
  }),

  rename: protectedProcedure.input(displayNameInput).handler(async ({ input, context }) => {
    await requireOwnedActiveInstance(input.instanceId, context.session.user.id);
    const updated = await prisma.cockpitInstance.update({
      where: { id: input.instanceId },
      data: { displayName: input.displayName },
    });
    return serializeInstance(updated);
  }),

  revoke: protectedProcedure
    .input(z.object({ instanceId: z.string().min(1) }))
    .handler(async ({ input, context }) => {
      const instance = await prisma.cockpitInstance.findUnique({ where: { id: input.instanceId } });
      if (!instance || instance.userId !== context.session.user.id) {
        throw new ORPCError("NOT_FOUND", { message: "Instance not found." });
      }
      await prisma.cockpitInstance.update({
        where: { id: input.instanceId },
        data: { status: "REVOKED", revokedAt: new Date() },
      });
      return { success: true };
    }),

  mintConnectorToken: publicProcedure.input(connectorTokenInput).handler(async ({ input }) => {
    const instance = await findInstanceForToken(input.instanceId, input.instanceToken);
    const maxInstances = await limit(instance.userId, "instances");
    if (maxInstances < 1) {
      throw new ORPCError("FORBIDDEN", {
        message: "This account cannot connect owned instances on its current plan.",
      });
    }
    await prisma.cockpitInstance.update({
      where: { id: instance.id },
      data: { lastSeenAt: new Date() },
    });
    const relayTarget = await resolveConnectorRelayTarget(input.relayId, instance.id);
    const relay = await createRelayToken(
      {
        tokenType: "connector",
        instanceId: instance.id,
        userId: instance.userId,
        grants: [],
      },
      relayTarget.relayId,
    );
    return { token: relay.token, expiresAt: relay.expiresAt, relayUrl: relayTarget.relayUrl };
  }),

  listRelayCandidates: publicProcedure.input(instanceTokenInput).handler(async ({ input }) => {
    await findInstanceForToken(input.instanceId, input.instanceToken);
    return { relays: await relayCandidatesForInstance() };
  }),

  mintClientToken: protectedProcedure
    .input(z.object({ instanceId: z.string().min(1) }))
    .handler(async ({ input, context }) => {
      const instance = await requireActiveInstanceForAccess(input.instanceId);
      const isOwner = instance.userId === context.session.user.id;
      const grants = isOwner
        ? ownerAgentGrants
        : await activeSharedRelayGrantsForUser({
            instanceId: instance.id,
            userId: context.session.user.id,
            scopes: ["agent", "agent_readonly", "project_files"],
          });
      if (!isOwner && grants.length === 0) {
        throw new ORPCError("NOT_FOUND", { message: "Instance not found." });
      }
      const relayTarget = await resolveClientRelayTarget(instance.id);
      const relay = await createRelayToken(
        {
          tokenType: "client",
          instanceId: instance.id,
          userId: context.session.user.id,
          grants,
        },
        relayTarget.relayId,
      );
      return { token: relay.token, expiresAt: relay.expiresAt, relayUrl: relayTarget.relayUrl };
    }),

  mintTerminalClientToken: protectedProcedure
    .input(z.object({ instanceId: z.string().min(1) }))
    .handler(async ({ input, context }) => {
      const instance = await requireActiveInstanceForAccess(input.instanceId);
      const isOwner = instance.userId === context.session.user.id;
      const grants = isOwner
        ? ownerTerminalGrant
        : await activeSharedRelayGrantsForUser({
            instanceId: instance.id,
            userId: context.session.user.id,
            scopes: ["terminal"],
          });
      if (!isOwner && grants.length === 0) {
        throw new ORPCError("NOT_FOUND", { message: "Instance not found." });
      }
      let stepUpExpiresAt: Date | null = null;
      if (isOwner) {
        const user = await prisma.user.findUnique({
          where: { id: context.session.user.id },
          select: { terminalStepUpRelaxed: true },
        });
        const stepUpRequired =
          context.session.user.twoFactorEnabled === true && user?.terminalStepUpRelaxed !== true;
        if (stepUpRequired && !hasRecentStepUp(context.session.session.createdAt)) {
          throw new ORPCError("FORBIDDEN", {
            message: "Recent reauthentication is required before opening a terminal.",
          });
        }
        stepUpExpiresAt = stepUpRequired
          ? terminalStepUpExpiresAt(context.session.session.createdAt)
          : null;
      }
      const relayTarget = await resolveClientRelayTarget(instance.id);
      const relay = await createRelayToken(
        {
          tokenType: "client",
          instanceId: instance.id,
          userId: context.session.user.id,
          grants,
        },
        relayTarget.relayId,
      );
      return {
        token: relay.token,
        expiresAt: relay.expiresAt,
        relayUrl: relayTarget.relayUrl,
        stepUpExpiresAt,
      };
    }),
};
