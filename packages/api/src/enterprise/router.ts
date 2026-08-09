import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import {
  encodeRemoteAdminApprovalEvidenceV1,
  encodeRemoteCredentialRegistryV1,
  type RemoteAdminOperation,
  remoteAdminOperationRequiresDualControl,
  tagProtocolIdBytes,
} from "@flycockpit/cockpit-protocol";
import prisma from "@flycockpit/db";
import { env } from "@flycockpit/env/server";
import { enterpriseLogExportQueue } from "@flycockpit/queue";
import { ORPCError } from "@orpc/server";
import { z } from "zod";
import { adminOr404Procedure, protectedProcedure, publicProcedure } from "../index";
import { logEnterpriseAudit } from "./audit";
import {
  createEnterpriseExportInputSchema,
  enterpriseIngestInputSchema,
  enterprisePolicyUpdateInputSchema,
} from "./contracts";
import { createEnterpriseExportDownloadUrl } from "./log-export";
import {
  authenticateEnterpriseInstance,
  getPrimaryOrgForUser,
  policyFromOrg,
  requireEnterpriseLogExport,
  requireOrgAdmin,
  slugifyOrgName,
} from "./orgs";
import { classifyRemotePolicyRevision } from "./remote-admin-policy";
import { REMOTE_ADMIN_ACTIONS, roleCanStartAction } from "./remote-admin-roles";
import {
  approvalChallenge,
  REMOTE_ADMIN_CEREMONY_TTL_MS,
  verifyRemoteAdminAssertion,
} from "./remote-admin-webauthn";

const orgIdInput = z.object({ orgId: z.string().min(1) });
const exportIdInput = z.object({ exportId: z.string().min(1) });
const remoteAdminActionSchema = z.enum(REMOTE_ADMIN_ACTIONS);
const SECURITY_ADMIN_BOOTSTRAP_TTL_MS = 15 * 60 * 1000;
const APPROVAL_TTL_MS = 15 * 60 * 1000;
const approvalOperationSchema = z.number().int().min(1).max(9);
const remotePolicyStrengthSchema = z.object({
  minimumProtocolVersion: z.number().int().min(1),
  minimumKeyBits: z.number().int().min(128),
  sessionTtlSeconds: z.number().int().min(1),
  attemptGrantTtlSeconds: z.number().int().min(1),
  requireDeviceTrust: z.boolean(),
  requireDaemonTrust: z.boolean(),
});
const uuidBytes = (uuid: string) => new Uint8Array(Buffer.from(uuid.replaceAll("-", ""), "hex"));
const u64Bytes = (value: bigint) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value);
  return bytes;
};
const signStepUpReference = (id: string) =>
  `${id}.${createHmac("sha256", env.BETTER_AUTH_SECRET)
    .update(`flycockpit-remote-admin-step-up-v1\0${id}`)
    .digest("base64url")}`;
const parseStepUpReference = (reference: string) => {
  const [id, signature, extra] = reference.split(".");
  if (!id || !signature || extra || id.length !== 43 || signature.length !== 43)
    throw new ORPCError("UNAUTHORIZED", { message: "Step-up reference is invalid." });
  const expected = signStepUpReference(id).slice(44);
  if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected)))
    throw new ORPCError("UNAUTHORIZED", { message: "Step-up reference is invalid." });
  return id;
};
const base64urlBytes = (value: string, expectedLength?: number) => {
  if (!/^[A-Za-z0-9_-]+$/.test(value))
    throw new ORPCError("BAD_REQUEST", { message: "Invalid passkey response." });
  const bytes = new Uint8Array(Buffer.from(value, "base64url"));
  if (expectedLength !== undefined && bytes.length !== expectedLength)
    throw new ORPCError("BAD_REQUEST", { message: "Invalid passkey response." });
  return bytes;
};

export const enterpriseRouter = {
  authorizeRemotePolicyRevision: protectedProcedure
    .input(
      z.object({
        orgId: z.string().min(1),
        current: remotePolicyStrengthSchema,
        proposed: remotePolicyStrengthSchema,
        canonicalRequestDigest: z.string().max(64),
        operationEpoch: z.string().regex(/^(0|[1-9][0-9]{0,19})$/),
        approvalIds: z.array(z.string().uuid()).min(1).max(2),
      }),
    )
    .handler(async ({ input }) => {
      const classification = classifyRemotePolicyRevision(input.current, input.proposed);
      const expectedCount = classification === "weakening" ? 2 : 1;
      if (input.approvalIds.length !== expectedCount)
        throw new ORPCError("PRECONDITION_FAILED", {
          message: "Policy approval cardinality is invalid.",
        });
      const now = new Date(),
        digest = base64urlBytes(input.canonicalRequestDigest, 32);
      return prisma.$transaction(
        async (tx) => {
          const registry = await tx.remoteAdminRegistry.findUnique({
            where: { orgId: input.orgId },
          });
          if (!registry)
            throw new ORPCError("NOT_FOUND", { message: "Remote policy registry not found." });
          const approvals = await tx.remoteAdminApproval.findMany({
            where: {
              id: { in: input.approvalIds },
              orgId: input.orgId,
              operation: 4,
              operationEpoch: BigInt(input.operationEpoch),
              canonicalRequestDigest: Buffer.from(digest),
              registryGeneration: registry.generation,
              consumedAt: null,
              expiresAt: { gte: now },
            },
          });
          if (approvals.length !== expectedCount)
            throw new ORPCError("PRECONDITION_FAILED", {
              message: "Current policy approval is required.",
            });
          if (classification === "weakening") {
            if (
              approvals[0]!.principalId === approvals[1]!.principalId ||
              !approvals.some((approval) => approval.role === "OWNER") ||
              !approvals.some((approval) => approval.role === "SECURITY_ADMIN")
            )
              throw new ORPCError("PRECONDITION_FAILED", {
                message: "Dual policy approval is invalid.",
              });
          } else if (approvals[0]!.role !== "SECURITY_ADMIN") {
            throw new ORPCError("PRECONDITION_FAILED", {
              message: "Security administrator approval is required.",
            });
          }
          if (
            (
              await tx.remoteAdminApproval.updateMany({
                where: { id: { in: input.approvalIds }, consumedAt: null },
                data: { consumedAt: now },
              })
            ).count !== expectedCount
          )
            throw new ORPCError("CONFLICT", { message: "Policy approval was already consumed." });
          return {
            authorized: true as const,
            classification,
            registryGeneration: String(registry.generation),
            operationEpoch: input.operationEpoch,
          };
        },
        { isolationLevel: "Serializable" },
      );
    }),

  pendingRemoteAdminRegistration: protectedProcedure.handler(async ({ context }) => {
    const now = new Date();
    const ceremony = await prisma.remoteAdminCeremony.findFirst({
      where: {
        principalId: context.session.user.id,
        kind: { in: ["SECURITY_ADMIN_BOOTSTRAP", "REGISTRATION"] },
        consumedAt: null,
        expiresAt: { gte: now },
        challengeBytes: { not: null },
      },
      orderBy: { createdAt: "desc" },
      include: {
        EnterpriseOrg: {
          include: { RemoteAdminRegistry: true },
        },
      },
    });
    const registry = ceremony?.EnterpriseOrg?.RemoteAdminRegistry;
    if (!ceremony?.challengeBytes || !registry) return null;
    return {
      challengeId: ceremony.id,
      challenge: Buffer.from(ceremony.challengeBytes).toString("base64url"),
      orgId: ceremony.orgId!,
      orgName: ceremony.EnterpriseOrg!.name,
      role: "SECURITY_ADMIN" as const,
      registryGeneration: String(registry.generation + 1n),
      reviewDigest: Buffer.from(ceremony.requestDigest).toString("base64url"),
      expiresAt: String(ceremony.expiresAt.getTime()),
      rpId: registry.rpId,
      origin: registry.origin,
      userVerification: "required" as const,
      residentKey: "preferred" as const,
      algorithm: -7 as const,
    };
  }),

  beginGovernedSecurityAdminRegistration: protectedProcedure
    .input(
      z.object({
        orgId: z.string().min(1),
        nomineeId: z.string().min(1),
        canonicalRequestDigest: z.string().max(64),
        operationEpoch: z.string().regex(/^(0|[1-9][0-9]{0,19})$/),
        ownerApprovalId: z.string().uuid(),
        securityApprovalId: z.string().uuid(),
      }),
    )
    .handler(async ({ input }) => {
      const now = new Date(),
        digest = base64urlBytes(input.canonicalRequestDigest, 32);
      const epoch = BigInt(input.operationEpoch),
        challenge = randomBytes(32),
        challengeId = randomUUID();
      return prisma.$transaction(
        async (tx) => {
          const registry = await tx.remoteAdminRegistry.findUnique({
            where: { orgId: input.orgId },
          });
          const nominee = await tx.enterpriseOrgMember.findUnique({
            where: {
              orgId_userId: { orgId: input.orgId, userId: input.nomineeId },
            },
          });
          if (!registry?.securityAdminBootstrapSealed || nominee?.role !== "MEMBER")
            throw new ORPCError("PRECONDITION_FAILED", { message: "Nominee is not eligible." });
          const approvals = await tx.remoteAdminApproval.findMany({
            where: {
              id: { in: [input.ownerApprovalId, input.securityApprovalId] },
              orgId: input.orgId,
              operation: 8,
              operationEpoch: epoch,
              canonicalRequestDigest: Buffer.from(digest),
              consumedAt: null,
              expiresAt: { gte: now },
              registryGeneration: registry.generation,
            },
          });
          if (
            approvals.length !== 2 ||
            approvals[0]!.principalId === approvals[1]!.principalId ||
            !approvals.some((approval) => approval.role === "OWNER") ||
            !approvals.some((approval) => approval.role === "SECURITY_ADMIN")
          )
            throw new ORPCError("PRECONDITION_FAILED", {
              message: "Dual role approvals are required.",
            });
          if (
            (
              await tx.remoteAdminApproval.updateMany({
                where: { id: { in: approvals.map((a) => a.id) }, consumedAt: null },
                data: { consumedAt: now },
              })
            ).count !== 2
          )
            throw new ORPCError("CONFLICT", { message: "Role approvals were consumed." });
          await tx.remoteAdminCeremony.create({
            data: {
              id: challengeId,
              orgId: input.orgId,
              principalId: input.nomineeId,
              nomineeId: input.nomineeId,
              kind: "REGISTRATION",
              action: "security_role_change",
              requestDigest: Buffer.from(digest),
              requestPayload: {
                nomineeId: input.nomineeId,
                governed: true,
                operationEpoch: input.operationEpoch,
              },
              challengeHash: createHash("sha256").update(challenge).digest(),
              challengeBytes: challenge,
              issuedAt: now,
              expiresAt: new Date(now.getTime() + SECURITY_ADMIN_BOOTSTRAP_TTL_MS),
            },
          });
          return {
            challengeId,
            challenge: challenge.toString("base64url"),
            expiresAt: String(now.getTime() + SECURITY_ADMIN_BOOTSTRAP_TTL_MS),
            rpId: registry.rpId,
            origin: registry.origin,
            userVerification: "required" as const,
            residentKey: "preferred" as const,
            algorithm: -7 as const,
          };
        },
        { isolationLevel: "Serializable" },
      );
    }),

  revokeSecurityAdminRole: protectedProcedure
    .input(
      z.object({
        orgId: z.string().min(1),
        principalId: z.string().min(1),
        canonicalRequestDigest: z.string().max(64),
        operationEpoch: z.string().regex(/^(0|[1-9][0-9]{0,19})$/),
        ownerApprovalId: z.string().uuid(),
        securityApprovalId: z.string().uuid(),
      }),
    )
    .handler(async ({ input, context }) => {
      const now = new Date(),
        digest = base64urlBytes(input.canonicalRequestDigest, 32);
      return prisma.$transaction(
        async (tx) => {
          const registry = await tx.remoteAdminRegistry.findUnique({
            where: { orgId: input.orgId },
          });
          const member = await tx.enterpriseOrgMember.findUnique({
            where: {
              orgId_userId: { orgId: input.orgId, userId: input.principalId },
            },
          });
          if (!registry || member?.role !== "SECURITY_ADMIN")
            throw new ORPCError("NOT_FOUND", { message: "Security administrator not found." });
          if (
            (await tx.enterpriseOrgMember.count({
              where: {
                orgId: input.orgId,
                role: "SECURITY_ADMIN",
                userId: { not: input.principalId },
              },
            })) < 1
          )
            throw new ORPCError("PRECONDITION_FAILED", {
              message: "Last security administrator is protected.",
            });
          const approvals = await tx.remoteAdminApproval.findMany({
            where: {
              id: { in: [input.ownerApprovalId, input.securityApprovalId] },
              orgId: input.orgId,
              operation: 8,
              operationEpoch: BigInt(input.operationEpoch),
              canonicalRequestDigest: Buffer.from(digest),
              consumedAt: null,
              expiresAt: { gte: now },
              registryGeneration: registry.generation,
            },
          });
          if (
            approvals.length !== 2 ||
            approvals[0]!.principalId === approvals[1]!.principalId ||
            !approvals.some((approval) => approval.role === "OWNER") ||
            !approvals.some((approval) => approval.role === "SECURITY_ADMIN")
          )
            throw new ORPCError("PRECONDITION_FAILED", {
              message: "Dual role approvals are required.",
            });
          if (
            (
              await tx.remoteAdminApproval.updateMany({
                where: { id: { in: approvals.map((a) => a.id) }, consumedAt: null },
                data: { consumedAt: now },
              })
            ).count !== 2
          )
            throw new ORPCError("CONFLICT", { message: "Role approvals were consumed." });
          await tx.enterpriseOrgMember.update({
            where: { id: member.id },
            data: { role: "MEMBER" },
          });
          await tx.remoteAdminCredential.updateMany({
            where: { orgId: input.orgId, principalId: input.principalId, state: "ACTIVE" },
            data: { state: "REVOKED", revokedAt: now },
          });
          const nextGeneration = registry.generation + 1n;
          await tx.remoteAdminRegistry.update({
            where: { id: registry.id },
            data: { generation: nextGeneration },
          });
          await tx.remoteAdminApproval.updateMany({
            where: { orgId: input.orgId, consumedAt: null },
            data: { consumedAt: now },
          });
          await tx.enterpriseAuditLog.create({
            data: {
              orgId: input.orgId,
              userId: context.session.user.id,
              action: "enterprise.remote_admin.security_role.revoke",
              entity: "EnterpriseOrgMember",
              entityId: member.id,
              metadata: {
                principalId: input.principalId,
                registryGeneration: String(nextGeneration),
              },
            },
          });
          return { role: "MEMBER" as const, registryGeneration: String(nextGeneration) };
        },
        { isolationLevel: "Serializable" },
      );
    }),

  exportRemoteCredentialRegistry: protectedProcedure
    .input(z.object({ orgId: z.string().min(1), stepUp: z.string().length(87) }))
    .handler(async ({ input, context }) => {
      const now = new Date();
      return prisma.$transaction(
        async (tx) => {
          const registry = await tx.remoteAdminRegistry.findUnique({
            where: { orgId: input.orgId },
          });
          if (!registry?.securityAdminBootstrapSealed)
            throw new ORPCError("PRECONDITION_FAILED", {
              message: "Credential registry is not sealed.",
            });
          if (
            (
              await tx.remoteAdminStepUp.updateMany({
                where: {
                  id: parseStepUpReference(input.stepUp),
                  orgId: input.orgId,
                  principalId: context.session.user.id,
                  role: "SECURITY_ADMIN",
                  action: "tenant_signer_configuration",
                  sessionId: context.session.session.id,
                  consumedAt: null,
                  expiresAt: { gte: now },
                },
                data: { consumedAt: now },
              })
            ).count !== 1
          )
            throw new ORPCError("UNAUTHORIZED", {
              message: "Security administrator step-up is required.",
            });
          const credentials = await tx.remoteAdminCredential.findMany({
            where: { orgId: input.orgId, role: { in: ["OWNER", "SECURITY_ADMIN"] } },
          });
          const bytes = encodeRemoteCredentialRegistryV1({
            tenantId: tagProtocolIdBytes("tenant", new Uint8Array(registry.tenantProtocolId)),
            registryGeneration: registry.generation,
            rpId: registry.rpId,
            origin: registry.origin,
            entries: credentials.map((credential) => ({
              principalId: tagProtocolIdBytes(
                "account",
                new Uint8Array(credential.principalProtocolId),
              ),
              role: credential.role === "OWNER" ? 1 : 2,
              credentialIdHash: new Uint8Array(credential.credentialIdHash),
              coseAlg: -7,
              p256X: new Uint8Array(credential.p256X),
              p256Y: new Uint8Array(credential.p256Y),
              declaredCustody:
                credential.declaredCustody === "SYNCED_PASSKEY"
                  ? 1
                  : credential.declaredCustody === "EXTERNAL_SECURITY_KEY"
                    ? 2
                    : 3,
              state: credential.state === "ACTIVE" ? 1 : 2,
              createdAt: BigInt(Math.floor(credential.createdAt.getTime() / 1000)),
              revokedAt: credential.revokedAt
                ? BigInt(Math.floor(credential.revokedAt.getTime() / 1000))
                : null,
            })),
          });
          return {
            registry: Buffer.from(bytes).toString("base64url"),
            digest: createHash("sha256").update(bytes).digest("base64url"),
            registryGeneration: String(registry.generation),
          };
        },
        { isolationLevel: "Serializable" },
      );
    }),

  revokeRemoteAdminCredential: protectedProcedure
    .input(
      z.object({
        orgId: z.string().min(1),
        credentialIdHash: z.string().max(64),
        ownerApprovalId: z.string().uuid(),
        securityApprovalId: z.string().uuid(),
        operationEpoch: z.string().regex(/^(0|[1-9][0-9]{0,19})$/),
        canonicalRequestDigest: z.string().max(64),
      }),
    )
    .handler(async ({ input, context }) => {
      const credentialIdHash = base64urlBytes(input.credentialIdHash, 32);
      const digest = base64urlBytes(input.canonicalRequestDigest, 32);
      const now = new Date(),
        epoch = BigInt(input.operationEpoch);
      return prisma.$transaction(
        async (tx) => {
          const registry = await tx.remoteAdminRegistry.findUnique({
            where: { orgId: input.orgId },
          });
          const credential = await tx.remoteAdminCredential.findUnique({
            where: {
              orgId_credentialIdHash: {
                orgId: input.orgId,
                credentialIdHash: Buffer.from(credentialIdHash),
              },
            },
          });
          if (!registry || !credential || credential.state !== "ACTIVE")
            throw new ORPCError("NOT_FOUND", { message: "Active credential not found." });
          const approvals = await tx.remoteAdminApproval.findMany({
            where: {
              id: { in: [input.ownerApprovalId, input.securityApprovalId] },
              orgId: input.orgId,
              operation: 9,
              operationEpoch: epoch,
              canonicalRequestDigest: Buffer.from(digest),
              consumedAt: null,
              expiresAt: { gte: now },
              registryGeneration: registry.generation,
            },
          });
          if (
            approvals.length !== 2 ||
            approvals[0]!.principalId === approvals[1]!.principalId ||
            !approvals.some((approval) => approval.role === "OWNER") ||
            !approvals.some((approval) => approval.role === "SECURITY_ADMIN")
          )
            throw new ORPCError("PRECONDITION_FAILED", {
              message: "Dual credential approvals are required.",
            });
          const remaining = await tx.remoteAdminCredential.count({
            where: {
              orgId: input.orgId,
              role: credential.role,
              state: "ACTIVE",
              id: { not: credential.id },
            },
          });
          if (remaining < 1)
            throw new ORPCError("PRECONDITION_FAILED", {
              message: "The last qualifying administrator credential is protected.",
            });
          if (
            (
              await tx.remoteAdminApproval.updateMany({
                where: { id: { in: approvals.map((a) => a.id) }, consumedAt: null },
                data: { consumedAt: now },
              })
            ).count !== 2
          )
            throw new ORPCError("CONFLICT", { message: "Credential approvals were consumed." });
          await tx.remoteAdminCredential.update({
            where: { id: credential.id },
            data: { state: "REVOKED", revokedAt: now },
          });
          const nextGeneration = registry.generation + 1n;
          await tx.remoteAdminRegistry.update({
            where: { id: registry.id },
            data: { generation: nextGeneration },
          });
          await tx.remoteAdminApproval.updateMany({
            where: { orgId: input.orgId, consumedAt: null },
            data: { consumedAt: now },
          });
          await tx.enterpriseAuditLog.create({
            data: {
              orgId: input.orgId,
              userId: context.session.user.id,
              action: "enterprise.remote_admin.credential.revoke",
              entity: "RemoteAdminCredential",
              entityId: credential.id,
              metadata: {
                registryGeneration: String(nextGeneration),
                credentialIdHash: Buffer.from(credentialIdHash).toString("hex"),
              },
            },
          });
          return { registryGeneration: String(nextGeneration) };
        },
        { isolationLevel: "Serializable" },
      );
    }),

  proposeRemoteAdminRecovery: protectedProcedure
    .input(
      z.object({
        orgId: z.string().min(1),
        canonicalRequestDigest: z.string().max(64),
        operationEpoch: z.string().regex(/^(0|[1-9][0-9]{0,19})$/),
        ownerApprovalId: z.string().uuid(),
        securityApprovalId: z.string().uuid(),
      }),
    )
    .handler(async ({ input }) => {
      const digest = base64urlBytes(input.canonicalRequestDigest, 32);
      const epoch = BigInt(input.operationEpoch),
        now = new Date();
      return prisma.$transaction(
        async (tx) => {
          const approvals = await tx.remoteAdminApproval.findMany({
            where: {
              id: {
                in: [input.ownerApprovalId, input.securityApprovalId],
              },
              orgId: input.orgId,
              operation: 7,
              operationEpoch: epoch,
              canonicalRequestDigest: Buffer.from(digest),
              consumedAt: null,
              expiresAt: { gte: now },
            },
          });
          if (
            approvals.length !== 2 ||
            approvals[0]!.principalId === approvals[1]!.principalId ||
            Buffer.from(approvals[0]!.credentialIdHash).equals(
              Buffer.from(approvals[1]!.credentialIdHash),
            ) ||
            new Set(approvals.map((approval) => approval.role)).size !== 2 ||
            !approvals.some((approval) => approval.role === "OWNER") ||
            !approvals.some((approval) => approval.role === "SECURITY_ADMIN")
          )
            throw new ORPCError("PRECONDITION_FAILED", {
              message: "Distinct recovery approvals are required.",
            });
          const registry = await tx.remoteAdminRegistry.findUnique({
            where: { orgId: input.orgId },
          });
          if (
            !registry ||
            approvals.some((approval) => approval.registryGeneration !== registry.generation)
          )
            throw new ORPCError("CONFLICT", { message: "Recovery approvals are stale." });
          const active = await tx.remoteAdminCredential.count({
            where: {
              orgId: input.orgId,
              state: "ACTIVE",
              OR: approvals.map((approval) => ({
                principalId: approval.principalId,
                credentialIdHash: approval.credentialIdHash,
                role: approval.role,
              })),
            },
          });
          if (active !== 2)
            throw new ORPCError("CONFLICT", { message: "Recovery credentials changed." });
          if (
            (
              await tx.remoteAdminApproval.updateMany({
                where: { id: { in: approvals.map((a) => a.id) }, consumedAt: null },
                data: { consumedAt: now },
              })
            ).count !== 2
          )
            throw new ORPCError("CONFLICT", {
              message: "Recovery approvals were already consumed.",
            });
          const owner = approvals.find((approval) => approval.role === "OWNER")!;
          const security = approvals.find((approval) => approval.role === "SECURITY_ADMIN")!;
          const proposal = await tx.remoteAdminRecoveryProposal.create({
            data: {
              id: randomUUID(),
              orgId: input.orgId,
              requestDigest: Buffer.from(digest),
              operationEpoch: epoch,
              ownerPrincipalId: owner.principalId,
              securityPrincipalId: security.principalId,
              coolingEndsAt: new Date(now.getTime() + registry.recoveryCoolingSeconds * 1000),
              expiresAt: new Date(now.getTime() + registry.recoveryProposalTtlSeconds * 1000),
              state: "COOLING",
            },
          });
          const recipients = (
            await tx.enterpriseOrgMember.findMany({
              where: { orgId: input.orgId, role: { in: ["OWNER", "SECURITY_ADMIN"] } },
              select: { userId: true },
            })
          ).map((m) => m.userId);
          await tx.remoteAdminNotificationOutbox.create({
            data: {
              orgId: input.orgId,
              event: "remote_admin.recovery.proposed",
              recipients,
              RecipientRows: { create: recipients.map((userId) => ({ userId })) },
              payload: {
                proposalId: proposal.id,
                coolingEndsAt: String(proposal.coolingEndsAt.getTime()),
                expiresAt: String(proposal.expiresAt.getTime()),
              },
            },
          });
          return proposal;
        },
        { isolationLevel: "Serializable" },
      );
    }),

  reconfirmRemoteAdminRecovery: protectedProcedure
    .input(z.object({ proposalId: z.string().uuid(), stepUp: z.string().length(87) }))
    .handler(async ({ input, context }) => {
      const now = new Date();
      return prisma.$transaction(
        async (tx) => {
          const proposal = await tx.remoteAdminRecoveryProposal.findUnique({
            where: { id: input.proposalId },
          });
          if (
            !proposal ||
            !["COOLING", "READY"].includes(proposal.state) ||
            now < proposal.coolingEndsAt ||
            now > proposal.expiresAt ||
            ![proposal.ownerPrincipalId, proposal.securityPrincipalId].includes(
              context.session.user.id,
            )
          )
            throw new ORPCError("PRECONDITION_FAILED", {
              message: "Recovery cannot be reconfirmed.",
            });
          const role =
            proposal.ownerPrincipalId === context.session.user.id ? "OWNER" : "SECURITY_ADMIN";
          if (
            (
              await tx.remoteAdminStepUp.updateMany({
                where: {
                  id: parseStepUpReference(input.stepUp),
                  orgId: proposal.orgId,
                  principalId: context.session.user.id,
                  role,
                  action: "recovery",
                  sessionId: context.session.session.id,
                  consumedAt: null,
                  expiresAt: { gte: now },
                },
                data: { consumedAt: now },
              })
            ).count !== 1
          )
            throw new ORPCError("UNAUTHORIZED", { message: "Fresh recovery step-up is required." });
          const data =
            role === "OWNER" ? { ownerReconfirmedAt: now } : { securityReconfirmedAt: now };
          const updated = await tx.remoteAdminRecoveryProposal.update({
            where: { id: proposal.id },
            data,
          });
          const ready =
            updated.ownerReconfirmedAt !== null && updated.securityReconfirmedAt !== null;
          if (ready)
            await tx.remoteAdminRecoveryProposal.update({
              where: { id: proposal.id },
              data: { state: "READY" },
            });
          return {
            proposalId: proposal.id,
            state: ready ? ("READY" as const) : ("COOLING" as const),
          };
        },
        { isolationLevel: "Serializable" },
      );
    }),

  cancelRemoteAdminRecovery: protectedProcedure
    .input(z.object({ proposalId: z.string().uuid(), stepUp: z.string().length(87) }))
    .handler(async ({ input, context }) => {
      const now = new Date();
      return prisma.$transaction(
        async (tx) => {
          const proposal = await tx.remoteAdminRecoveryProposal.findUnique({
            where: { id: input.proposalId },
          });
          const owner =
            proposal &&
            (await tx.enterpriseOrgMember.findUnique({
              where: {
                orgId_userId: { orgId: proposal.orgId, userId: context.session.user.id },
              },
            }));
          if (
            !proposal ||
            !owner ||
            owner.role !== "OWNER" ||
            !["PENDING", "COOLING", "READY"].includes(proposal.state) ||
            now > proposal.expiresAt
          )
            throw new ORPCError("FORBIDDEN", { message: "Recovery cannot be cancelled." });
          if (
            (
              await tx.remoteAdminStepUp.updateMany({
                where: {
                  id: parseStepUpReference(input.stepUp),
                  orgId: proposal.orgId,
                  principalId: context.session.user.id,
                  role: "OWNER",
                  action: "recovery",
                  sessionId: context.session.session.id,
                  consumedAt: null,
                  expiresAt: { gte: now },
                },
                data: { consumedAt: now },
              })
            ).count !== 1
          )
            throw new ORPCError("UNAUTHORIZED", { message: "Fresh owner step-up is required." });
          const cancelled = await tx.remoteAdminRecoveryProposal.update({
            where: { id: proposal.id },
            data: { state: "CANCELLED", cancelledById: context.session.user.id },
          });
          const recipients = (
            await tx.enterpriseOrgMember.findMany({
              where: { orgId: proposal.orgId, role: { in: ["OWNER", "SECURITY_ADMIN"] } },
              select: { userId: true },
            })
          ).map((m) => m.userId);
          await tx.remoteAdminNotificationOutbox.create({
            data: {
              orgId: proposal.orgId,
              event: "remote_admin.recovery.cancelled",
              recipients,
              RecipientRows: { create: recipients.map((userId) => ({ userId })) },
              payload: { proposalId: proposal.id },
            },
          });
          return cancelled;
        },
        { isolationLevel: "Serializable" },
      );
    }),

  executeRemoteAdminRecovery: protectedProcedure
    .input(z.object({ proposalId: z.string().uuid() }))
    .handler(async ({ input, context }) => {
      const now = new Date();
      return prisma.$transaction(
        async (tx) => {
          const proposal = await tx.remoteAdminRecoveryProposal.findUnique({
            where: { id: input.proposalId },
          });
          if (
            proposal?.state !== "READY" ||
            now > proposal.expiresAt ||
            proposal.ownerReconfirmedAt === null ||
            proposal.securityReconfirmedAt === null ||
            proposal.ownerReconfirmedAt < proposal.coolingEndsAt ||
            proposal.securityReconfirmedAt < proposal.coolingEndsAt ||
            ![proposal.ownerPrincipalId, proposal.securityPrincipalId].includes(
              context.session.user.id,
            )
          )
            throw new ORPCError("PRECONDITION_FAILED", { message: "Recovery is not executable." });
          const active = await tx.enterpriseOrgMember.count({
            where: {
              orgId: proposal.orgId,
              OR: [
                { userId: proposal.ownerPrincipalId, role: "OWNER" },
                { userId: proposal.securityPrincipalId, role: "SECURITY_ADMIN" },
              ],
            },
          });
          if (active !== 2)
            throw new ORPCError("CONFLICT", { message: "Recovery quorum changed." });
          const executed = await tx.remoteAdminRecoveryProposal.update({
            where: { id: proposal.id },
            data: { state: "EXECUTED", executedAt: now },
          });
          await tx.enterpriseAuditLog.create({
            data: {
              orgId: proposal.orgId,
              userId: context.session.user.id,
              action: "enterprise.remote_admin.recovery.execute",
              entity: "RemoteAdminRecoveryProposal",
              entityId: proposal.id,
              metadata: { operationEpoch: String(proposal.operationEpoch) },
            },
          });
          return executed;
        },
        { isolationLevel: "Serializable" },
      );
    }),

  beginRemoteAdminApproval: protectedProcedure
    .input(
      z.object({
        orgId: z.string().min(1),
        operation: approvalOperationSchema,
        canonicalRequestDigest: z.string().max(64),
        operationEpoch: z.string().regex(/^(0|[1-9][0-9]{0,19})$/),
        policyWeakening: z.boolean().default(false),
      }),
    )
    .handler(async ({ input, context }) => {
      const operation = input.operation as RemoteAdminOperation;
      const digest = base64urlBytes(input.canonicalRequestDigest, 32);
      const epoch = BigInt(input.operationEpoch);
      if (epoch > 18_446_744_073_709_551_615n)
        throw new ORPCError("BAD_REQUEST", { message: "Operation epoch is invalid." });
      const member = await prisma.enterpriseOrgMember.findUnique({
        where: {
          orgId_userId: { orgId: input.orgId, userId: context.session.user.id },
        },
      });
      const dual =
        remoteAdminOperationRequiresDualControl(operation) ||
        (operation === 4 && input.policyWeakening);
      if (!member || member.role === "MEMBER" || (!dual && member.role !== "SECURITY_ADMIN"))
        throw new ORPCError("FORBIDDEN", { message: "This role cannot approve the operation." });
      const registry = await prisma.remoteAdminRegistry.findUnique({
        where: { orgId: input.orgId },
      });
      if (!registry?.securityAdminBootstrapSealed)
        throw new ORPCError("PRECONDITION_FAILED", {
          message: "Security administration is not activated.",
        });
      const nonce = randomBytes(32);
      const operationBytes = new Uint8Array([
        operation,
        ...digest,
        ...u64Bytes(epoch),
        input.policyWeakening ? 1 : 0,
      ]);
      const challenge = await approvalChallenge(operationBytes, nonce);
      const challengeId = randomUUID(),
        issuedAt = new Date();
      await prisma.remoteAdminCeremony.create({
        data: {
          id: challengeId,
          orgId: input.orgId,
          principalId: context.session.user.id,
          sessionId: context.session.session.id,
          kind: "APPROVAL",
          action: `operation:${operation}`,
          requestDigest: Buffer.from(digest),
          requestPayload: {
            operation,
            operationEpoch: input.operationEpoch,
            policyWeakening: input.policyWeakening,
          },
          challengeHash: createHash("sha256").update(challenge).digest(),
          challengeBytes: Buffer.from(challenge),
          issuedAt,
          expiresAt: new Date(issuedAt.getTime() + APPROVAL_TTL_MS),
        },
      });
      return {
        challengeId,
        challenge: Buffer.from(challenge).toString("base64url"),
        expiresAt: String(issuedAt.getTime() + APPROVAL_TTL_MS),
        rpId: registry.rpId,
        origin: registry.origin,
        userVerification: "required" as const,
      };
    }),

  completeRemoteAdminApproval: protectedProcedure
    .input(
      z.object({
        challengeId: z.string().uuid(),
        credentialIdHash: z.string().max(64),
        authenticatorData: z.string().max(1400),
        clientDataJson: z.string().max(5500),
        signatureDer: z.string().max(128),
      }),
    )
    .handler(async ({ input, context }) => {
      const ceremony = await prisma.remoteAdminCeremony.findUnique({
        where: { id: input.challengeId },
        include: { EnterpriseOrg: { include: { RemoteAdminRegistry: true } } },
      });
      const registry = ceremony?.EnterpriseOrg?.RemoteAdminRegistry;
      if (
        !ceremony ||
        !registry ||
        ceremony.kind !== "APPROVAL" ||
        ceremony.principalId !== context.session.user.id ||
        ceremony.sessionId !== context.session.session.id ||
        ceremony.consumedAt ||
        ceremony.expiresAt.getTime() < Date.now() ||
        ceremony.issuedAt.getTime() + APPROVAL_TTL_MS !== ceremony.expiresAt.getTime()
      )
        throw new ORPCError("UNAUTHORIZED", {
          message: "Approval ceremony is invalid or expired.",
        });
      const payload = ceremony.requestPayload as {
        operation?: unknown;
        operationEpoch?: unknown;
        policyWeakening?: unknown;
      } | null;
      if (typeof payload?.operation !== "number" || typeof payload.operationEpoch !== "string")
        throw new ORPCError("CONFLICT", { message: "Approval scope is invalid." });
      const operation = payload.operation as RemoteAdminOperation;
      const credentialIdHash = base64urlBytes(input.credentialIdHash, 32);
      const credential = await prisma.remoteAdminCredential.findUnique({
        where: {
          orgId_credentialIdHash: {
            orgId: ceremony.orgId!,
            credentialIdHash: Buffer.from(credentialIdHash),
          },
        },
      });
      if (
        !credential ||
        credential.principalId !== context.session.user.id ||
        credential.state !== "ACTIVE" ||
        credential.role === "MEMBER" ||
        credential.registryGeneration !== registry.generation
      )
        throw new ORPCError("UNAUTHORIZED", { message: "Approval credential is not current." });
      const dual =
        remoteAdminOperationRequiresDualControl(operation) ||
        (operation === 4 && payload.policyWeakening === true);
      if (!dual && credential.role !== "SECURITY_ADMIN")
        throw new ORPCError("FORBIDDEN", {
          message: "Security administrator approval is required.",
        });
      const clientDataJson = base64urlBytes(input.clientDataJson);
      let challengeText: unknown;
      try {
        challengeText = (
          JSON.parse(new TextDecoder().decode(clientDataJson)) as { challenge?: unknown }
        ).challenge;
      } catch {
        throw new ORPCError("BAD_REQUEST", { message: "Invalid approval assertion." });
      }
      if (typeof challengeText !== "string")
        throw new ORPCError("BAD_REQUEST", { message: "Invalid approval assertion." });
      const challenge = base64urlBytes(challengeText, 32);
      if (
        !createHash("sha256").update(challenge).digest().equals(Buffer.from(ceremony.challengeHash))
      )
        throw new ORPCError("UNAUTHORIZED", { message: "Approval challenge mismatch." });
      const authenticatorData = base64urlBytes(input.authenticatorData);
      const verified = await verifyRemoteAdminAssertion({
        assertion: {
          credentialIdHash,
          authenticatorData,
          clientDataJson,
          signatureDer: base64urlBytes(input.signatureDer),
        },
        credential: {
          principalId: tagProtocolIdBytes(
            "account",
            new Uint8Array(credential.principalProtocolId),
          ),
          role: credential.role === "OWNER" ? 1 : 2,
          credentialIdHash,
          coseAlg: -7,
          p256X: new Uint8Array(credential.p256X),
          p256Y: new Uint8Array(credential.p256Y),
          declaredCustody: 3,
          state: 1,
          createdAt: BigInt(Math.floor(credential.createdAt.getTime() / 1000)),
          revokedAt: null,
        },
        policy: { rpId: registry.rpId, origin: registry.origin },
        expectedChallenge: challenge,
      });
      const issuedAt = BigInt(Math.floor(ceremony.issuedAt.getTime() / 1000));
      const expiresAt = BigInt(Math.floor(ceremony.expiresAt.getTime() / 1000));
      const evidenceBytes = encodeRemoteAdminApprovalEvidenceV1({
        tenantId: tagProtocolIdBytes("tenant", new Uint8Array(registry.tenantProtocolId)),
        principalId: tagProtocolIdBytes("account", new Uint8Array(credential.principalProtocolId)),
        role: credential.role === "OWNER" ? 1 : 2,
        registryGeneration: registry.generation,
        credentialIdHash,
        operation,
        canonicalRequestDigest: new Uint8Array(ceremony.requestDigest),
        operationEpoch: BigInt(payload.operationEpoch),
        issuedAt,
        expiresAt,
        challengeId: uuidBytes(ceremony.id),
        challengeHash: new Uint8Array(ceremony.challengeHash),
        rpId: registry.rpId,
        origin: registry.origin,
        authenticatorData,
        clientDataJson,
        coseAlg: -7,
        signatureP1363: verified.signatureP1363,
      });
      const now = new Date(),
        approvalId = randomUUID();
      await prisma.$transaction(
        async (tx) => {
          if (
            (
              await tx.remoteAdminCeremony.updateMany({
                where: { id: ceremony.id, consumedAt: null, expiresAt: { gte: now } },
                data: { consumedAt: now },
              })
            ).count !== 1
          )
            throw new ORPCError("CONFLICT", { message: "Approval ceremony was already consumed." });
          await tx.remoteAdminApproval.create({
            data: {
              id: approvalId,
              orgId: ceremony.orgId!,
              principalId: context.session.user.id,
              role: credential.role,
              credentialIdHash: credential.credentialIdHash,
              registryGeneration: registry.generation,
              operation,
              canonicalRequestDigest: ceremony.requestDigest,
              operationEpoch: BigInt(payload.operationEpoch),
              challengeId: ceremony.id,
              evidenceDigest: createHash("sha256").update(evidenceBytes).digest(),
              evidenceBytes: Buffer.from(evidenceBytes),
              issuedAt: ceremony.issuedAt,
              expiresAt: ceremony.expiresAt,
            },
          });
        },
        { isolationLevel: "Serializable" },
      );
      return {
        approvalId,
        evidence: Buffer.from(evidenceBytes).toString("base64url"),
        expiresAt: String(ceremony.expiresAt.getTime()),
      };
    }),

  beginSecurityAdminBootstrap: protectedProcedure
    .input(
      z.object({
        orgId: z.string().min(1),
        nomineeId: z.string().min(1),
        stepUp: z.string().length(87),
      }),
    )
    .handler(async ({ input, context }) => {
      if (input.nomineeId === context.session.user.id)
        throw new ORPCError("BAD_REQUEST", { message: "Security administrator must be distinct." });
      const now = new Date();
      const registry = await prisma.remoteAdminRegistry.findUnique({
        where: { orgId: input.orgId },
      });
      const nominee = await prisma.enterpriseOrgMember.findUnique({
        where: {
          orgId_userId: { orgId: input.orgId, userId: input.nomineeId },
        },
      });
      if (
        !registry?.ownerBootstrapSealed ||
        registry.securityAdminBootstrapSealed ||
        nominee?.role !== "MEMBER" ||
        (await prisma.enterpriseOrgMember.count({
          where: {
            orgId: input.orgId,
            role: "SECURITY_ADMIN",
          },
        })) !== 0
      )
        throw new ORPCError("PRECONDITION_FAILED", {
          message: "Security administrator bootstrap is closed.",
        });
      const challenge = randomBytes(32),
        challengeId = randomUUID();
      await prisma.$transaction(
        async (tx) => {
          const consumed = await tx.remoteAdminStepUp.updateMany({
            where: {
              id: parseStepUpReference(input.stepUp),
              orgId: input.orgId,
              principalId: context.session.user.id,
              role: "OWNER",
              action: "credential_governance",
              sessionId: context.session.session.id,
              consumedAt: null,
              expiresAt: { gte: now },
            },
            data: { consumedAt: now },
          });
          if (consumed.count !== 1)
            throw new ORPCError("UNAUTHORIZED", { message: "Owner step-up is invalid." });
          const digest = createHash("sha256")
            .update(
              JSON.stringify({
                orgId: input.orgId,
                nomineeId: input.nomineeId,
                role: "SECURITY_ADMIN",
                generation: String(registry.generation + 1n),
              }),
            )
            .digest();
          await tx.remoteAdminCeremony.create({
            data: {
              id: challengeId,
              orgId: input.orgId,
              principalId: input.nomineeId,
              nominatorId: context.session.user.id,
              nomineeId: input.nomineeId,
              kind: "SECURITY_ADMIN_BOOTSTRAP",
              action: "security_role_change",
              requestDigest: digest,
              requestPayload: { nomineeId: input.nomineeId },
              challengeHash: createHash("sha256").update(challenge).digest(),
              challengeBytes: challenge,
              issuedAt: now,
              expiresAt: new Date(now.getTime() + SECURITY_ADMIN_BOOTSTRAP_TTL_MS),
            },
          });
        },
        { isolationLevel: "Serializable" },
      );
      return {
        challengeId,
        challenge: challenge.toString("base64url"),
        expiresAt: String(now.getTime() + SECURITY_ADMIN_BOOTSTRAP_TTL_MS),
        rpId: registry.rpId,
        origin: registry.origin,
        userVerification: "required" as const,
        residentKey: "preferred" as const,
        algorithm: -7 as const,
      };
    }),

  completeOwnerBootstrap: adminOr404Procedure
    .input(
      z.object({
        challengeId: z.string().uuid(),
        credentialIdHash: z.string().max(64),
        publicKeySpki: z.string().max(256),
        declaredCustody: z.enum(["SYNCED_PASSKEY", "EXTERNAL_SECURITY_KEY", "UNKNOWN"]),
        authenticatorData: z.string().max(1400),
        clientDataJson: z.string().max(5500),
        signatureDer: z.string().max(128),
      }),
    )
    .handler(async ({ input, context }) => {
      const submissionDigest = createHash("sha256").update(JSON.stringify(input)).digest();
      const ceremony = await prisma.remoteAdminCeremony.findUnique({
        where: { id: input.challengeId },
      });
      if (ceremony?.consumedAt && ceremony.committedResult) {
        if (
          !ceremony.committedDigest ||
          !submissionDigest.equals(Buffer.from(ceremony.committedDigest))
        )
          throw new ORPCError("CONFLICT", { message: "Owner bootstrap retry changed." });
        const committed = ceremony.committedResult as { orgId?: unknown };
        if (typeof committed.orgId === "string") {
          const org = await prisma.enterpriseOrg.findUnique({ where: { id: committed.orgId } });
          if (org) return { org, policy: policyFromOrg(org), registryGeneration: "1" };
        }
      }
      if (
        ceremony?.kind !== "OWNER_BOOTSTRAP" ||
        ceremony.orgId !== null ||
        ceremony.principalId !== context.session.user.id ||
        ceremony.sessionId !== context.session.session.id ||
        ceremony.consumedAt ||
        ceremony.expiresAt.getTime() < Date.now() ||
        ceremony.issuedAt.getTime() + REMOTE_ADMIN_CEREMONY_TTL_MS !== ceremony.expiresAt.getTime()
      )
        throw new ORPCError("UNAUTHORIZED", { message: "Owner bootstrap is invalid or expired." });
      const payload = ceremony.requestPayload as { name?: unknown; slug?: unknown } | null;
      if (typeof payload?.name !== "string" || typeof payload.slug !== "string")
        throw new ORPCError("CONFLICT", { message: "Owner bootstrap payload is invalid." });
      const credentialIdHash = base64urlBytes(input.credentialIdHash, 32);
      const spki = base64urlBytes(input.publicKeySpki);
      let publicJwk: JsonWebKey;
      try {
        const publicKey = await crypto.subtle.importKey(
          "spki",
          spki,
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["verify"],
        );
        publicJwk = await crypto.subtle.exportKey("jwk", publicKey);
      } catch {
        throw new ORPCError("BAD_REQUEST", { message: "Invalid ES256 public key." });
      }
      if (!publicJwk.x || !publicJwk.y || publicJwk.crv !== "P-256")
        throw new ORPCError("BAD_REQUEST", { message: "Invalid ES256 public key." });
      const p256X = base64urlBytes(publicJwk.x, 32),
        p256Y = base64urlBytes(publicJwk.y, 32);
      const clientDataJson = base64urlBytes(input.clientDataJson);
      let challengeText: unknown;
      try {
        challengeText = (
          JSON.parse(new TextDecoder().decode(clientDataJson)) as { challenge?: unknown }
        ).challenge;
      } catch {
        throw new ORPCError("BAD_REQUEST", { message: "Invalid passkey response." });
      }
      if (typeof challengeText !== "string")
        throw new ORPCError("BAD_REQUEST", { message: "Invalid passkey response." });
      const challenge = base64urlBytes(challengeText, 32);
      if (
        !createHash("sha256").update(challenge).digest().equals(Buffer.from(ceremony.challengeHash))
      )
        throw new ORPCError("UNAUTHORIZED", { message: "Passkey challenge mismatch." });
      const principalProtocolId = randomBytes(16),
        tenantProtocolId = randomBytes(16);
      const publicOrigin = new URL(env.BETTER_AUTH_URL);
      await verifyRemoteAdminAssertion({
        assertion: {
          credentialIdHash,
          authenticatorData: base64urlBytes(input.authenticatorData),
          clientDataJson,
          signatureDer: base64urlBytes(input.signatureDer),
        },
        credential: {
          principalId: tagProtocolIdBytes("account", principalProtocolId),
          role: 1,
          credentialIdHash,
          coseAlg: -7,
          p256X,
          p256Y,
          declaredCustody:
            input.declaredCustody === "SYNCED_PASSKEY"
              ? 1
              : input.declaredCustody === "EXTERNAL_SECURITY_KEY"
                ? 2
                : 3,
          state: 1,
          createdAt: BigInt(Math.floor(Date.now() / 1000)),
          revokedAt: null,
        },
        policy: { rpId: publicOrigin.hostname, origin: publicOrigin.origin },
        expectedChallenge: challenge,
      });
      const now = new Date();
      return prisma.$transaction(
        async (tx) => {
          const consumed = await tx.remoteAdminCeremony.updateMany({
            where: { id: ceremony.id, consumedAt: null, expiresAt: { gte: now } },
            data: { consumedAt: now },
          });
          if (consumed.count !== 1)
            throw new ORPCError("CONFLICT", { message: "Owner bootstrap was already consumed." });
          const org = await tx.enterpriseOrg.create({
            data: {
              name: payload.name as string,
              slug: payload.slug as string,
              Members: { create: { userId: context.session.user.id, role: "OWNER" } },
            },
          });
          const registry = await tx.remoteAdminRegistry.create({
            data: {
              orgId: org.id,
              tenantProtocolId,
              generation: 1n,
              rpId: publicOrigin.hostname,
              origin: publicOrigin.origin,
              ownerBootstrapSealed: true,
            },
          });
          await tx.remoteAdminCredential.create({
            data: {
              orgId: org.id,
              principalId: context.session.user.id,
              principalProtocolId,
              role: "OWNER",
              credentialIdHash: Buffer.from(credentialIdHash),
              p256X: Buffer.from(p256X),
              p256Y: Buffer.from(p256Y),
              declaredCustody: input.declaredCustody,
              registryGeneration: 1n,
            },
          });
          await tx.remoteAdminCredentialCounter.create({
            data: {
              registryId: registry.id,
              tenantId: tenantProtocolId,
              credentialIdHash: Buffer.from(credentialIdHash),
              registryGeneration: 1n,
            },
          });
          await tx.enterpriseAuditLog.create({
            data: {
              orgId: org.id,
              userId: context.session.user.id,
              action: "enterprise.remote_admin.owner_bootstrap",
              entity: "RemoteAdminRegistry",
              entityId: registry.id,
              metadata: {
                registryGeneration: "1",
                credentialIdHash: Buffer.from(credentialIdHash).toString("hex"),
              },
            },
          });
          await tx.remoteAdminNotificationOutbox.create({
            data: {
              orgId: org.id,
              event: "remote_admin.owner_bootstrap.committed",
              recipients: [context.session.user.id],
              payload: { registryGeneration: "1" },
              RecipientRows: { create: [{ userId: context.session.user.id }] },
            },
          });
          await tx.remoteAdminCeremony.update({
            where: { id: ceremony.id },
            data: { committedResult: { orgId: org.id }, committedDigest: submissionDigest },
          });
          return { org, policy: policyFromOrg(org), registryGeneration: "1" };
        },
        { isolationLevel: "Serializable" },
      );
    }),

  completeSecurityAdminBootstrap: protectedProcedure
    .input(
      z.object({
        challengeId: z.string().uuid(),
        accept: z.literal(true),
        credentialIdHash: z.string().max(64),
        publicKeySpki: z.string().max(256),
        declaredCustody: z.enum(["SYNCED_PASSKEY", "EXTERNAL_SECURITY_KEY", "UNKNOWN"]),
        authenticatorData: z.string().max(1400),
        clientDataJson: z.string().max(5500),
        signatureDer: z.string().max(128),
      }),
    )
    .handler(async ({ input, context }) => {
      const submissionDigest = createHash("sha256").update(JSON.stringify(input)).digest();
      const ceremony = await prisma.remoteAdminCeremony.findUnique({
        where: { id: input.challengeId },
        include: { EnterpriseOrg: { include: { RemoteAdminRegistry: true } } },
      });
      if (ceremony?.consumedAt && ceremony.committedResult) {
        if (
          !ceremony.committedDigest ||
          !submissionDigest.equals(Buffer.from(ceremony.committedDigest))
        )
          throw new ORPCError("CONFLICT", { message: "Security bootstrap retry changed." });
        return ceremony.committedResult;
      }
      const registry = ceremony?.EnterpriseOrg?.RemoteAdminRegistry;
      const isClosedBootstrap = ceremony?.kind === "SECURITY_ADMIN_BOOTSTRAP";
      if (
        !ceremony ||
        !registry ||
        (!isClosedBootstrap && ceremony.kind !== "REGISTRATION") ||
        ceremony.principalId !== context.session.user.id ||
        ceremony.nomineeId !== context.session.user.id ||
        ceremony.consumedAt ||
        ceremony.expiresAt.getTime() < Date.now() ||
        ceremony.issuedAt.getTime() + SECURITY_ADMIN_BOOTSTRAP_TTL_MS !==
          ceremony.expiresAt.getTime()
      )
        throw new ORPCError("UNAUTHORIZED", {
          message: "Security bootstrap is invalid or expired.",
        });
      const credentialIdHash = base64urlBytes(input.credentialIdHash, 32);
      const spki = base64urlBytes(input.publicKeySpki);
      let jwk: JsonWebKey;
      try {
        const key = await crypto.subtle.importKey(
          "spki",
          spki,
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["verify"],
        );
        jwk = await crypto.subtle.exportKey("jwk", key);
      } catch {
        throw new ORPCError("BAD_REQUEST", { message: "Invalid ES256 public key." });
      }
      if (!jwk.x || !jwk.y || jwk.crv !== "P-256")
        throw new ORPCError("BAD_REQUEST", { message: "Invalid ES256 public key." });
      const p256X = base64urlBytes(jwk.x, 32),
        p256Y = base64urlBytes(jwk.y, 32);
      const clientDataJson = base64urlBytes(input.clientDataJson);
      let challengeText: unknown;
      try {
        challengeText = (
          JSON.parse(new TextDecoder().decode(clientDataJson)) as { challenge?: unknown }
        ).challenge;
      } catch {
        throw new ORPCError("BAD_REQUEST", { message: "Invalid passkey response." });
      }
      if (typeof challengeText !== "string")
        throw new ORPCError("BAD_REQUEST", { message: "Invalid passkey response." });
      const challenge = base64urlBytes(challengeText, 32);
      if (
        !createHash("sha256").update(challenge).digest().equals(Buffer.from(ceremony.challengeHash))
      )
        throw new ORPCError("UNAUTHORIZED", { message: "Passkey challenge mismatch." });
      const principalProtocolId = randomBytes(16);
      await verifyRemoteAdminAssertion({
        assertion: {
          credentialIdHash,
          authenticatorData: base64urlBytes(input.authenticatorData),
          clientDataJson,
          signatureDer: base64urlBytes(input.signatureDer),
        },
        credential: {
          principalId: tagProtocolIdBytes("account", principalProtocolId),
          role: 2,
          credentialIdHash,
          coseAlg: -7,
          p256X,
          p256Y,
          declaredCustody:
            input.declaredCustody === "SYNCED_PASSKEY"
              ? 1
              : input.declaredCustody === "EXTERNAL_SECURITY_KEY"
                ? 2
                : 3,
          state: 1,
          createdAt: BigInt(Math.floor(Date.now() / 1000)),
          revokedAt: null,
        },
        policy: { rpId: registry.rpId, origin: registry.origin },
        expectedChallenge: challenge,
      });
      const now = new Date(),
        nextGeneration = registry.generation + 1n;
      const result = await prisma.$transaction(
        async (tx) => {
          if (
            (
              await tx.remoteAdminCeremony.updateMany({
                where: { id: ceremony.id, consumedAt: null, expiresAt: { gte: now } },
                data: { consumedAt: now },
              })
            ).count !== 1
          )
            throw new ORPCError("CONFLICT", {
              message: "Security bootstrap was already consumed.",
            });
          if (
            (
              await tx.remoteAdminRegistry.updateMany({
                where: {
                  id: registry.id,
                  generation: registry.generation,
                  securityAdminBootstrapSealed: !isClosedBootstrap,
                },
                data: { generation: nextGeneration, securityAdminBootstrapSealed: true },
              })
            ).count !== 1
          )
            throw new ORPCError("CONFLICT", { message: "Security bootstrap raced." });
          if (
            (
              await tx.enterpriseOrgMember.updateMany({
                where: { orgId: ceremony.orgId!, userId: context.session.user.id, role: "MEMBER" },
                data: { role: "SECURITY_ADMIN" },
              })
            ).count !== 1
          )
            throw new ORPCError("CONFLICT", { message: "Nominee account changed." });
          await tx.remoteAdminCredential.create({
            data: {
              orgId: ceremony.orgId!,
              principalId: context.session.user.id,
              principalProtocolId,
              role: "SECURITY_ADMIN",
              credentialIdHash: Buffer.from(credentialIdHash),
              p256X: Buffer.from(p256X),
              p256Y: Buffer.from(p256Y),
              declaredCustody: input.declaredCustody,
              registryGeneration: nextGeneration,
            },
          });
          await tx.remoteAdminCredentialCounter.create({
            data: {
              registryId: registry.id,
              tenantId: registry.tenantProtocolId,
              credentialIdHash: Buffer.from(credentialIdHash),
              registryGeneration: nextGeneration,
            },
          });
          await tx.enterpriseAuditLog.create({
            data: {
              orgId: ceremony.orgId!,
              userId: context.session.user.id,
              action: isClosedBootstrap
                ? "enterprise.remote_admin.security_bootstrap"
                : "enterprise.remote_admin.security_role.grant",
              entity: "RemoteAdminRegistry",
              entityId: registry.id,
              metadata: { registryGeneration: String(nextGeneration) },
            },
          });
          const recipients = (
            await tx.enterpriseOrgMember.findMany({
              where: { orgId: ceremony.orgId!, role: { in: ["OWNER", "SECURITY_ADMIN"] } },
              select: { userId: true },
            })
          ).map((member) => member.userId);
          await tx.remoteAdminNotificationOutbox.create({
            data: {
              orgId: ceremony.orgId!,
              event: isClosedBootstrap
                ? "remote_admin.security_bootstrap.committed"
                : "remote_admin.security_role.granted",
              recipients,
              payload: {
                principalId: context.session.user.id,
                registryGeneration: String(nextGeneration),
              },
              RecipientRows: { create: recipients.map((userId) => ({ userId })) },
            },
          });
          const committed = {
            orgId: ceremony.orgId!,
            role: "SECURITY_ADMIN" as const,
            registryGeneration: String(nextGeneration),
          };
          await tx.remoteAdminCeremony.update({
            where: { id: ceremony.id },
            data: {
              committedDigest: submissionDigest,
              committedResult: committed,
            },
          });
          return committed;
        },
        { isolationLevel: "Serializable" },
      );
      return result;
    }),

  beginRemoteAdminStepUp: protectedProcedure
    .input(z.object({ orgId: z.string().min(1), action: remoteAdminActionSchema }))
    .handler(async ({ input, context }) => {
      await requireEnterpriseLogExport(context.session.user.id);
      const member = await prisma.enterpriseOrgMember.findUnique({
        where: { orgId_userId: { orgId: input.orgId, userId: context.session.user.id } },
        select: { role: true },
      });
      if (!member || !roleCanStartAction(member.role, input.action))
        throw new ORPCError("FORBIDDEN", {
          message: "This enterprise role cannot perform the action.",
        });
      const registry = await prisma.remoteAdminRegistry.findUnique({
        where: { orgId: input.orgId },
      });
      if (!registry?.ownerBootstrapSealed)
        throw new ORPCError("PRECONDITION_FAILED", {
          message: "Remote administration is not activated.",
        });
      const challenge = randomBytes(32);
      const id = randomUUID();
      const expiresAt = new Date(Date.now() + REMOTE_ADMIN_CEREMONY_TTL_MS);
      await prisma.remoteAdminCeremony.create({
        data: {
          id,
          orgId: input.orgId,
          principalId: context.session.user.id,
          sessionId: context.session.session.id,
          kind: "ASSERTION",
          action: input.action,
          requestDigest: createHash("sha256").update(input.action).digest(),
          challengeHash: createHash("sha256").update(challenge).digest(),
          challengeBytes: challenge,
          issuedAt: new Date(expiresAt.getTime() - REMOTE_ADMIN_CEREMONY_TTL_MS),
          expiresAt,
        },
      });
      return {
        challengeId: id,
        challenge: challenge.toString("base64url"),
        expiresAt,
        rpId: registry.rpId,
        origin: registry.origin,
        userVerification: "required" as const,
      };
    }),

  completeRemoteAdminStepUp: protectedProcedure
    .input(
      z.object({
        challengeId: z.string().uuid(),
        credentialIdHash: z.string().max(64),
        authenticatorData: z.string().max(1400),
        clientDataJson: z.string().max(5500),
        signatureDer: z.string().max(128),
      }),
    )
    .handler(async ({ input, context }) => {
      const ceremony = await prisma.remoteAdminCeremony.findUnique({
        where: { id: input.challengeId },
        include: { EnterpriseOrg: { include: { RemoteAdminRegistry: true } } },
      });
      const registry = ceremony?.EnterpriseOrg?.RemoteAdminRegistry;
      if (
        !ceremony ||
        !registry ||
        ceremony.kind !== "ASSERTION" ||
        ceremony.principalId !== context.session.user.id ||
        ceremony.sessionId !== context.session.session.id ||
        ceremony.consumedAt ||
        ceremony.expiresAt.getTime() < Date.now() ||
        ceremony.issuedAt.getTime() + REMOTE_ADMIN_CEREMONY_TTL_MS !== ceremony.expiresAt.getTime()
      )
        throw new ORPCError("UNAUTHORIZED", {
          message: "Passkey ceremony is invalid or expired.",
        });
      const credentialIdHash = base64urlBytes(input.credentialIdHash, 32);
      const credential = await prisma.remoteAdminCredential.findUnique({
        where: {
          orgId_credentialIdHash: {
            orgId: ceremony.orgId!,
            credentialIdHash: Buffer.from(credentialIdHash),
          },
        },
      });
      if (
        !credential ||
        credential.principalId !== context.session.user.id ||
        credential.state !== "ACTIVE" ||
        credential.registryGeneration !== registry.generation ||
        credential.role === "MEMBER"
      )
        throw new ORPCError("UNAUTHORIZED", { message: "Passkey credential is not active." });
      const clientDataJson = base64urlBytes(input.clientDataJson);
      let clientData: unknown;
      try {
        clientData = JSON.parse(new TextDecoder().decode(clientDataJson));
      } catch {
        throw new ORPCError("BAD_REQUEST", { message: "Invalid passkey response." });
      }
      const encodedChallenge = (clientData as { challenge?: unknown }).challenge;
      if (typeof encodedChallenge !== "string")
        throw new ORPCError("BAD_REQUEST", { message: "Invalid passkey response." });
      const challengeBytes = base64urlBytes(encodedChallenge, 32);
      if (
        !createHash("sha256")
          .update(challengeBytes)
          .digest()
          .equals(Buffer.from(ceremony.challengeHash))
      )
        throw new ORPCError("UNAUTHORIZED", { message: "Passkey challenge mismatch." });
      await verifyRemoteAdminAssertion({
        assertion: {
          credentialIdHash,
          authenticatorData: base64urlBytes(input.authenticatorData),
          clientDataJson,
          signatureDer: base64urlBytes(input.signatureDer),
        },
        credential: {
          principalId: tagProtocolIdBytes(
            "account",
            new Uint8Array(credential.principalProtocolId),
          ),
          role: credential.role === "OWNER" ? 1 : 2,
          credentialIdHash,
          coseAlg: -7,
          p256X: new Uint8Array(credential.p256X),
          p256Y: new Uint8Array(credential.p256Y),
          declaredCustody:
            credential.declaredCustody === "SYNCED_PASSKEY"
              ? 1
              : credential.declaredCustody === "EXTERNAL_SECURITY_KEY"
                ? 2
                : 3,
          state: 1,
          createdAt: BigInt(Math.floor(credential.createdAt.getTime() / 1000)),
          revokedAt: null,
        },
        policy: { rpId: registry.rpId, origin: registry.origin },
        expectedChallenge: challengeBytes,
      });
      const now = new Date();
      const stepUpId = randomBytes(32).toString("base64url");
      await prisma.$transaction(
        async (tx) => {
          const consumed = await tx.remoteAdminCeremony.updateMany({
            where: { id: ceremony.id, consumedAt: null, expiresAt: { gte: now } },
            data: { consumedAt: now },
          });
          if (consumed.count !== 1)
            throw new ORPCError("CONFLICT", {
              message: "Passkey ceremony was already consumed.",
            });
          await tx.remoteAdminStepUp.create({
            data: {
              id: stepUpId,
              orgId: ceremony.orgId!,
              principalId: context.session.user.id,
              role: credential.role,
              credentialIdHash: credential.credentialIdHash,
              registryGeneration: credential.registryGeneration,
              action: ceremony.action,
              sessionId: context.session.session.id,
              challengeId: ceremony.id,
              issuedAt: now,
              expiresAt: new Date(now.getTime() + REMOTE_ADMIN_CEREMONY_TTL_MS),
            },
          });
        },
        { isolationLevel: "Serializable" },
      );
      return {
        stepUp: signStepUpReference(stepUpId),
        expiresAt: String(now.getTime() + REMOTE_ADMIN_CEREMONY_TTL_MS),
      };
    }),

  bootstrap: adminOr404Procedure
    .input(z.object({ name: z.string().trim().min(1).max(120).default("Enterprise") }).optional())
    .handler(async ({ input, context }) => {
      await requireEnterpriseLogExport(context.session.user.id);
      const existing = await prisma.enterpriseOrg.findFirst({ orderBy: { createdAt: "asc" } });
      if (existing)
        throw new ORPCError("CONFLICT", { message: "Enterprise organization already exists." });
      const name = input?.name ?? "Enterprise";
      const slug = slugifyOrgName(name);
      const canonical = JSON.stringify({ name, slug, principalId: context.session.user.id });
      const challenge = randomBytes(32);
      const id = randomUUID();
      const expiresAt = new Date(Date.now() + REMOTE_ADMIN_CEREMONY_TTL_MS);
      await prisma.remoteAdminCeremony.create({
        data: {
          id,
          orgId: null,
          principalId: context.session.user.id,
          nomineeId: context.session.user.id,
          sessionId: context.session.session.id,
          kind: "OWNER_BOOTSTRAP",
          action: "tenant_lifecycle",
          requestPayload: { name, slug },
          requestDigest: createHash("sha256").update(canonical).digest(),
          challengeHash: createHash("sha256").update(challenge).digest(),
          challengeBytes: challenge,
          issuedAt: new Date(expiresAt.getTime() - REMOTE_ADMIN_CEREMONY_TTL_MS),
          expiresAt,
        },
      });
      const publicOrigin = new URL(env.BETTER_AUTH_URL);
      return {
        challengeId: id,
        challenge: challenge.toString("base64url"),
        expiresAt,
        rpId: publicOrigin.hostname,
        origin: publicOrigin.origin,
        userVerification: "required" as const,
        residentKey: "preferred" as const,
        algorithm: -7 as const,
        creationDigest: Buffer.from(createHash("sha256").update(canonical).digest()).toString(
          "base64url",
        ),
      };
    }),

  overview: protectedProcedure.handler(async ({ context }) => {
    await requireEnterpriseLogExport(context.session.user.id);
    const membership = await getPrimaryOrgForUser(context.session.user.id);
    if (!membership) return { org: null, membership: null, policy: null };
    const [members, exports, instances, eventCount, recovery] = await Promise.all([
      prisma.enterpriseOrgMember.findMany({
        where: { orgId: membership.orgId },
        orderBy: [{ role: "asc" }, { createdAt: "asc" }],
        include: { User: { select: { id: true, name: true, email: true } } },
      }),
      prisma.enterpriseLogExport.findMany({
        where: { orgId: membership.orgId },
        orderBy: { createdAt: "desc" },
        take: 20,
      }),
      listOrgInstances(membership.orgId),
      prisma.enterpriseLogEvent.count({ where: { orgId: membership.orgId } }),
      prisma.remoteAdminRecoveryProposal.findFirst({
        where: { orgId: membership.orgId, state: { in: ["PENDING", "COOLING", "READY"] } },
        orderBy: { createdAt: "desc" },
        select: {
          id: true,
          state: true,
          coolingEndsAt: true,
          expiresAt: true,
          ownerReconfirmedAt: true,
          securityReconfirmedAt: true,
        },
      }),
    ]);
    return {
      org: membership.EnterpriseOrg,
      membership: { role: membership.role },
      policy: policyFromOrg(membership.EnterpriseOrg),
      members,
      exports,
      instances,
      eventCount,
      recovery,
    };
  }),

  updatePolicy: protectedProcedure
    .input(enterprisePolicyUpdateInputSchema)
    .handler(async ({ input, context }) => {
      await requireOrgAdmin(context.session.user.id, input.orgId, "tenant_lifecycle");
      const org = await prisma.enterpriseOrg.update({
        where: { id: input.orgId },
        data: {
          logSyncMandated: input.logSyncMandated,
          syncSessionEvents: input.syncSessionEvents,
          syncMessageEvents: input.syncMessageEvents,
          syncToolCallEvents: input.syncToolCallEvents,
          syncInferenceEvents: input.syncInferenceEvents,
          syncTruncationEvents: input.syncTruncationEvents,
          includeLocalModels: input.includeLocalModels,
          backfill: input.backfill,
          backlogPolicy: input.backlogPolicy,
          retentionDays: input.retentionDays,
          policyVersion: { increment: 1 },
        },
      });
      await logEnterpriseAudit({
        orgId: org.id,
        userId: context.session.user.id,
        action: "enterprise.policy.update",
        entity: "EnterpriseOrg",
        entityId: org.id,
        metadata: { policyVersion: org.policyVersion },
      });
      return { org, policy: policyFromOrg(org) };
    }),

  instancePolicy: publicProcedure
    .input(z.object({ instanceId: z.string().min(1), instanceToken: z.string().min(1) }))
    .handler(async ({ input }) => {
      const { org } = await authenticateEnterpriseInstance(input.instanceId, input.instanceToken);
      return policyFromOrg(org);
    }),

  ingest: publicProcedure.input(enterpriseIngestInputSchema).handler(async ({ input }) => {
    const { instance, org } = await authenticateEnterpriseInstance(
      input.instanceId,
      input.instanceToken,
    );
    await requireEnterpriseLogExport(instance.userId);
    const firstSeq = Math.min(...input.events.map((event) => event.seq));
    const lastSeq = Math.max(...input.events.map((event) => event.seq));
    const existing = await prisma.enterpriseLogBatch.findFirst({
      where: { instanceId: instance.id, firstSeq, lastSeq },
      select: { id: true, eventCount: true },
    });
    if (existing) {
      return {
        duplicate: true,
        acceptedEvents: 0,
        droppedEvents: input.events.length,
        policyVersion: org.policyVersion,
      };
    }

    const policy = policyFromOrg(org);
    const accepted = input.events.filter((event) => policy.logSync.eventKindPolicy[event.kind]);
    const batch = await prisma.enterpriseLogBatch.create({
      data: {
        orgId: org.id,
        instanceId: instance.id,
        userId: instance.userId,
        schemaVersion: input.schemaVersion,
        idempotencyKey: input.idempotencyKey,
        firstSeq,
        lastSeq,
        eventCount: accepted.length,
        policyVersion: org.policyVersion,
      },
    });
    await prisma.enterpriseLogEvent.createMany({
      data: accepted.map((event) => ({
        orgId: org.id,
        batchId: batch.id,
        instanceId: instance.id,
        userId: instance.userId,
        seq: event.seq,
        sessionId: event.sessionId,
        projectRoot: event.projectRoot,
        kind: event.kind,
        occurredAt: event.occurredAt ? new Date(event.occurredAt) : null,
        model: event.model,
        role: event.role,
        content: event.content,
        payload: event.payload,
        redactionVersion: event.redactionVersion,
        truncated: event.truncated,
      })),
      skipDuplicates: true,
    });
    return {
      duplicate: false,
      acceptedEvents: accepted.length,
      droppedEvents: input.events.length - accepted.length,
      policyVersion: org.policyVersion,
    };
  }),

  createExport: protectedProcedure
    .input(createEnterpriseExportInputSchema)
    .handler(async ({ input, context }) => {
      await requireOrgAdmin(context.session.user.id, input.filters.orgId, "enterprise_log_export");
      const exportRow = await prisma.enterpriseLogExport.create({
        data: {
          orgId: input.filters.orgId,
          requestedById: context.session.user.id,
          format: input.format,
          filters: input.filters,
        },
      });
      await enterpriseLogExportQueue.add("enterprise-log-export", { exportId: exportRow.id });
      await logEnterpriseAudit({
        orgId: input.filters.orgId,
        userId: context.session.user.id,
        action: "enterprise.export.create",
        entity: "EnterpriseLogExport",
        entityId: exportRow.id,
        metadata: { format: input.format, filters: input.filters },
      });
      return exportRow;
    }),

  listExports: protectedProcedure.input(orgIdInput).handler(async ({ input, context }) => {
    await requireOrgAdmin(context.session.user.id, input.orgId, "enterprise_log_export");
    return prisma.enterpriseLogExport.findMany({
      where: { orgId: input.orgId },
      orderBy: { createdAt: "desc" },
      take: 100,
    });
  }),

  downloadExport: protectedProcedure.input(exportIdInput).handler(async ({ input, context }) => {
    const exportRow = await prisma.enterpriseLogExport.findUnique({
      where: { id: input.exportId },
    });
    if (!exportRow) throw new ORPCError("NOT_FOUND", { message: "Export not found." });
    await requireOrgAdmin(context.session.user.id, exportRow.orgId, "enterprise_log_export");
    const signed = await createEnterpriseExportDownloadUrl(input.exportId);
    if (!signed) throw new ORPCError("CONFLICT", { message: "Export artifact is not ready." });
    await logEnterpriseAudit({
      orgId: exportRow.orgId,
      userId: context.session.user.id,
      action: "enterprise.export.download",
      entity: "EnterpriseLogExport",
      entityId: exportRow.id,
      metadata: { format: exportRow.format },
    });
    return signed;
  }),

  transparency: protectedProcedure.handler(async ({ context }) => {
    await requireEnterpriseLogExport(context.session.user.id);
    const membership = await getPrimaryOrgForUser(context.session.user.id);
    if (!membership) throw new ORPCError("NOT_FOUND", { message: "Enterprise org not found." });
    const [eventCount, batchCount, lastEvent] = await Promise.all([
      prisma.enterpriseLogEvent.count({
        where: { orgId: membership.orgId, userId: context.session.user.id },
      }),
      prisma.enterpriseLogBatch.count({
        where: { orgId: membership.orgId, userId: context.session.user.id },
      }),
      prisma.enterpriseLogEvent.findFirst({
        where: { orgId: membership.orgId, userId: context.session.user.id },
        orderBy: { createdAt: "desc" },
        select: { createdAt: true },
      }),
    ]);
    return {
      org: membership.EnterpriseOrg,
      policy: policyFromOrg(membership.EnterpriseOrg),
      stats: { eventCount, batchCount, lastSyncedAt: lastEvent?.createdAt ?? null },
    };
  }),
};

async function listOrgInstances(orgId: string) {
  const members = await prisma.enterpriseOrgMember.findMany({
    where: { orgId },
    select: { userId: true },
  });
  const userIds = members.map((member) => member.userId);
  if (userIds.length === 0) return [];
  return prisma.cockpitInstance.findMany({
    where: { userId: { in: userIds } },
    orderBy: [{ lastSeenAt: "desc" }, { createdAt: "desc" }],
    include: { User: { select: { id: true, name: true, email: true } } },
  });
}
