import prisma from "@flycockpit/db";
import { env } from "@flycockpit/env/server";
import { renderShareInvite, sendEmail } from "@flycockpit/mailer";
import { ORPCError } from "@orpc/server";
import { z } from "zod";
import { protectedProcedure } from "../index";
import {
  activeSharedRelayGrantsForUser,
  expireStaleInstanceAccessGrants,
  normalizeEmail,
  projectRootForGrant,
  projectRootKey,
  publishGrantRevocation,
  recordInstanceAuditEvent,
  requireActiveInstanceForAccess,
  type SharingScope,
  serializeGrant,
  sharingScopes,
  toDbScope,
} from "../lib/instance-sharing";

const scopeSchema = z.enum(sharingScopes);
const expirySchema = z.enum(["24h", "7d", "30d", "never"]);

const inviteInput = z.object({
  instanceId: z.string().min(1),
  email: z.email(),
  scopes: z.array(scopeSchema).min(1).max(sharingScopes.length),
  projectRoot: z.string().trim().min(1).max(4096).optional(),
  expiresIn: expirySchema.optional(),
});

const grantIdInput = z.object({ grantId: z.string().min(1) });
const renewInput = grantIdInput.extend({ expiresIn: expirySchema });

type GrantWithInstance = Awaited<ReturnType<typeof prisma.instanceAccessGrant.findMany>>[number] & {
  Instance: {
    id: string;
    displayName: string;
    hostname: string;
    revokedAt: Date | null;
    lastSeenAt: Date | null;
  };
};

function expiryDate(scopes: SharingScope[], preset: z.infer<typeof expirySchema> | undefined) {
  const effectivePreset = preset ?? (scopes.includes("terminal") ? "7d" : "never");
  if (effectivePreset === "never") return null;
  const hours = effectivePreset === "24h" ? 24 : effectivePreset === "7d" ? 24 * 7 : 24 * 30;
  return new Date(Date.now() + hours * 60 * 60 * 1000);
}

function sharingUrl(locale: string) {
  const base = new URL(env.BETTER_AUTH_URL);
  base.pathname = "/" + locale + "/instances";
  base.search = "";
  base.hash = "";
  return base.toString();
}

function scopeLabels(scopes: SharingScope[]) {
  return scopes.map((scope) => scope.replaceAll("_", " "));
}

async function requireOwnedInstance(instanceId: string, userId: string) {
  const instance = await requireActiveInstanceForAccess(instanceId);
  if (instance.userId !== userId) {
    throw new ORPCError("NOT_FOUND", { message: "Instance not found." });
  }
  return instance;
}

function serializeSharedInstanceGrant(grant: GrantWithInstance) {
  return {
    ...serializeGrant(grant),
    instance: {
      id: grant.Instance.id,
      displayName: grant.Instance.displayName,
      hostname: grant.Instance.hostname,
    },
  };
}

function instancePresence(instance: { revokedAt: Date | null; lastSeenAt: Date | null }) {
  if (instance.revokedAt) return "revoked";
  return instance.lastSeenAt && Date.now() - instance.lastSeenAt.getTime() < 45_000
    ? "online"
    : "offline";
}

export const instanceSharingRouter = {
  listForInstance: protectedProcedure
    .input(z.object({ instanceId: z.string().min(1) }))
    .handler(async ({ input, context }) => {
      await expireStaleInstanceAccessGrants();
      await requireOwnedInstance(input.instanceId, context.session.user.id);
      const [grants, auditEvents] = await Promise.all([
        prisma.instanceAccessGrant.findMany({
          where: { instanceId: input.instanceId },
          orderBy: [{ createdAt: "desc" }],
        }),
        prisma.instanceAuditEvent.findMany({
          where: { instanceId: input.instanceId },
          orderBy: [{ createdAt: "desc" }],
          take: 50,
        }),
      ]);
      return {
        grants: grants.map(serializeGrant),
        auditEvents: auditEvents.map((event) => ({
          id: event.id,
          instanceId: event.instanceId,
          actorUserId: event.actorUserId,
          kind: event.kind,
          metadataJson: event.metadataJson,
          createdAt: event.createdAt,
        })),
      };
    }),

  listPendingForMe: protectedProcedure.handler(async ({ context }) => {
    await expireStaleInstanceAccessGrants();
    const email = normalizeEmail(context.session.user.email);
    const grants = (await prisma.instanceAccessGrant.findMany({
      where: { granteeEmail: email, status: "PENDING" },
      include: { Instance: true },
      orderBy: [{ invitedAt: "desc" }],
    })) as GrantWithInstance[];
    return { invitations: grants.map(serializeSharedInstanceGrant) };
  }),

  listSharedWithMe: protectedProcedure.handler(async ({ context }) => {
    await expireStaleInstanceAccessGrants();
    const grants = (await prisma.instanceAccessGrant.findMany({
      where: {
        granteeUserId: context.session.user.id,
        status: "ACTIVE",
        OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
      },
      include: { Instance: true },
      orderBy: [{ updatedAt: "desc" }],
    })) as GrantWithInstance[];
    const byInstance = new Map<
      string,
      {
        instance: { id: string; displayName: string; hostname: string; presence: string };
        grants: ReturnType<typeof serializeGrant>[];
      }
    >();
    for (const grant of grants) {
      const entry = byInstance.get(grant.instanceId) ?? {
        instance: {
          id: grant.Instance.id,
          displayName: grant.Instance.displayName,
          hostname: grant.Instance.hostname,
          presence: instancePresence(grant.Instance),
        },
        grants: [],
      };
      entry.grants.push(serializeGrant(grant));
      byInstance.set(grant.instanceId, entry);
    }
    return { sharedInstances: [...byInstance.values()] };
  }),

  invite: protectedProcedure.input(inviteInput).handler(async ({ input, context }) => {
    const ownerId = context.session.user.id;
    const instance = await requireOwnedInstance(input.instanceId, ownerId);
    const email = normalizeEmail(input.email);
    if (email === normalizeEmail(context.session.user.email)) {
      throw new ORPCError("BAD_REQUEST", { message: "You cannot invite yourself." });
    }
    const scopes = [...new Set(input.scopes)];
    if (scopes.includes("terminal") && context.session.user.twoFactorEnabled !== true) {
      throw new ORPCError("FORBIDDEN", {
        message: "Enable two-factor authentication before granting terminal access.",
      });
    }
    const existingGrantees = await prisma.instanceAccessGrant.findMany({
      where: { instanceId: input.instanceId, status: { in: ["PENDING", "ACTIVE"] } },
      select: { granteeEmail: true },
    });
    const uniqueGrantees = new Set(existingGrantees.map((grant) => grant.granteeEmail));
    if (!uniqueGrantees.has(email) && uniqueGrantees.size >= env.COCKPIT_INSTANCE_GRANTEE_LIMIT) {
      throw new ORPCError("FORBIDDEN", { message: "This instance has reached its grantee limit." });
    }
    const grantee = await prisma.user.findUnique({
      where: { email },
      select: { id: true, email: true, locale: true },
    });
    const expiresAt = expiryDate(scopes, input.expiresIn);
    const created = [];
    const reused = [];
    for (const scope of scopes) {
      const projectRoot = projectRootForGrant(scope, input.projectRoot);
      const existing = await prisma.instanceAccessGrant.findFirst({
        where: {
          instanceId: input.instanceId,
          granteeEmail: email,
          scope: toDbScope(scope),
          projectRootKey: projectRootKey(scope, input.projectRoot),
          status: { in: ["PENDING", "ACTIVE"] },
        },
      });
      if (existing) {
        reused.push(existing);
        continue;
      }
      const grant = await prisma.instanceAccessGrant.create({
        data: {
          instanceId: input.instanceId,
          ownerId,
          granteeUserId: grantee?.id ?? null,
          granteeEmail: email,
          scope: toDbScope(scope),
          projectRoot,
          projectRootKey: projectRootKey(scope, input.projectRoot),
          status: "PENDING",
          expiresAt,
          createdBy: ownerId,
        },
      });
      created.push(grant);
      await recordInstanceAuditEvent({
        instanceId: input.instanceId,
        actorUserId: ownerId,
        kind: "grant_invited",
        metadata: { grantId: grant.id, email, scope, projectRoot },
      });
    }

    let emailSent = false;
    if (created.length > 0 || reused.length > 0) {
      try {
        const locale = grantee?.locale ?? context.session.user.locale ?? "en-US";
        const { subject, html } = renderShareInvite({
          ownerName: context.session.user.name || context.session.user.email,
          instanceName: instance.displayName,
          scopes: scopeLabels(scopes),
          acceptUrl: sharingUrl(locale),
          expiresAt,
          existingUser: Boolean(grantee),
          locale,
        });
        await sendEmail({ to: email, subject, html });
        emailSent = true;
      } catch (err) {
        console.error("[instance-sharing.invite] failed to send invite email", err);
      }
    }

    return { grants: [...created, ...reused].map(serializeGrant), emailSent };
  }),

  accept: protectedProcedure.input(grantIdInput).handler(async ({ input, context }) => {
    await expireStaleInstanceAccessGrants();
    const email = normalizeEmail(context.session.user.email);
    const grant = await prisma.instanceAccessGrant.findFirst({
      where: { id: input.grantId, granteeEmail: email, status: "PENDING" },
    });
    if (!grant) throw new ORPCError("NOT_FOUND", { message: "Invitation not found." });
    const updated = await prisma.instanceAccessGrant.update({
      where: { id: grant.id },
      data: { status: "ACTIVE", granteeUserId: context.session.user.id, acceptedAt: new Date() },
    });
    await recordInstanceAuditEvent({
      instanceId: updated.instanceId,
      actorUserId: context.session.user.id,
      kind: "grant_accepted",
      metadata: { grantId: updated.id, scope: serializeGrant(updated).scope },
    });
    return serializeGrant(updated);
  }),

  decline: protectedProcedure.input(grantIdInput).handler(async ({ input, context }) => {
    const email = normalizeEmail(context.session.user.email);
    const grant = await prisma.instanceAccessGrant.findFirst({
      where: { id: input.grantId, granteeEmail: email, status: "PENDING" },
    });
    if (!grant) throw new ORPCError("NOT_FOUND", { message: "Invitation not found." });
    const updated = await prisma.instanceAccessGrant.update({
      where: { id: grant.id },
      data: { status: "DECLINED" },
    });
    await recordInstanceAuditEvent({
      instanceId: updated.instanceId,
      actorUserId: context.session.user.id,
      kind: "grant_declined",
      metadata: { grantId: updated.id },
    });
    return serializeGrant(updated);
  }),

  revoke: protectedProcedure.input(grantIdInput).handler(async ({ input, context }) => {
    const grant = await prisma.instanceAccessGrant.findUnique({ where: { id: input.grantId } });
    if (!grant) throw new ORPCError("NOT_FOUND", { message: "Grant not found." });
    await requireOwnedInstance(grant.instanceId, context.session.user.id);
    const updated = await prisma.instanceAccessGrant.update({
      where: { id: grant.id },
      data: { status: "REVOKED", revokedAt: new Date() },
    });
    let disconnectSent = false;
    if (updated.granteeUserId) {
      disconnectSent = await publishGrantRevocation({
        userId: updated.granteeUserId,
        instanceId: updated.instanceId,
      });
    }
    await recordInstanceAuditEvent({
      instanceId: updated.instanceId,
      actorUserId: context.session.user.id,
      kind: "grant_revoked",
      metadata: { grantId: updated.id, disconnectSent },
    });
    return { grant: serializeGrant(updated), disconnectSent };
  }),

  renew: protectedProcedure.input(renewInput).handler(async ({ input, context }) => {
    const grant = await prisma.instanceAccessGrant.findUnique({ where: { id: input.grantId } });
    if (!grant) throw new ORPCError("NOT_FOUND", { message: "Grant not found." });
    await requireOwnedInstance(grant.instanceId, context.session.user.id);
    const scope = String(grant.scope) === "TERMINAL" ? "terminal" : "agent";
    const expiresAt = expiryDate([scope], input.expiresIn);
    const updated = await prisma.instanceAccessGrant.update({
      where: { id: grant.id },
      data: { status: grant.granteeUserId ? "ACTIVE" : "PENDING", expiresAt, revokedAt: null },
    });
    await recordInstanceAuditEvent({
      instanceId: updated.instanceId,
      actorUserId: context.session.user.id,
      kind: "grant_renewed",
      metadata: { grantId: updated.id, expiresAt },
    });
    return serializeGrant(updated);
  }),

  myRelayGrants: protectedProcedure
    .input(z.object({ instanceId: z.string().min(1), terminal: z.boolean().default(false) }))
    .handler(async ({ input, context }) => {
      const grants = await activeSharedRelayGrantsForUser({
        instanceId: input.instanceId,
        userId: context.session.user.id,
        scopes: input.terminal ? ["terminal"] : ["agent", "agent_readonly", "project_files"],
      });
      return { grants };
    }),
};
