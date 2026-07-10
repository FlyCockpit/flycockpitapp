import prisma from "@flycockpit/db";
import { ORPCError } from "@orpc/server";
import { z } from "zod";
import { parseInstanceToken, verifyInstanceSecret } from "./instance-credentials";
import {
  getMissingRelayControlConfigKeys,
  getRelayControlConfig,
  relayControlUrl,
} from "./relay-config";
import type { RelayGrant, RelayGrantScope } from "./relay-tokens";

export const sharingScopes = ["terminal", "agent", "agent_readonly", "project_files"] as const;
export type SharingScope = (typeof sharingScopes)[number];

type DbScope = "TERMINAL" | "AGENT" | "AGENT_READONLY" | "PROJECT_FILES";

type GrantRow = {
  id: string;
  instanceId: string;
  ownerId: string;
  granteeUserId: string | null;
  granteeEmail: string;
  scope: unknown;
  projectRoot: string | null;
  projectRootKey: string;
  status: unknown;
  invitedAt: Date;
  acceptedAt: Date | null;
  revokedAt: Date | null;
  expiresAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

export const ownerAgentGrants: RelayGrant[] = [
  { scope: "agent", projectRoot: null },
  { scope: "agent_readonly", projectRoot: null },
  { scope: "project_files", projectRoot: null },
];

export const ownerTerminalGrant: RelayGrant[] = [{ scope: "terminal", projectRoot: null }];

export function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

export function toDbScope(scope: SharingScope): DbScope {
  if (scope === "terminal") return "TERMINAL";
  if (scope === "agent") return "AGENT";
  if (scope === "agent_readonly") return "AGENT_READONLY";
  return "PROJECT_FILES";
}

export function fromDbScope(scope: unknown): SharingScope {
  const value = String(scope);
  if (value === "TERMINAL") return "terminal";
  if (value === "AGENT") return "agent";
  if (value === "AGENT_READONLY") return "agent_readonly";
  if (value === "PROJECT_FILES") return "project_files";
  throw new ORPCError("INTERNAL_SERVER_ERROR", { message: "Unknown sharing scope." });
}

export function projectRootKey(scope: SharingScope, projectRoot: string | null | undefined) {
  if (scope === "terminal") return "*";
  const trimmed = projectRoot?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : "*";
}

export function projectRootForGrant(scope: SharingScope, projectRoot: string | null | undefined) {
  if (scope === "terminal") return null;
  const key = projectRootKey(scope, projectRoot);
  return key === "*" ? null : key;
}

export async function publishGrantRevocation(input: { userId: string; instanceId: string }) {
  const url = relayControlUrl();
  const config = getRelayControlConfig();
  if (!url || !config) {
    const missing = getMissingRelayControlConfigKeys();
    console.warn(
      `[relay-control] publishGrantRevocation skipped; missing ${
        missing.join(", ") || "relay control config"
      }.`,
    );
    return false;
  }
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer " + config.controlSecret,
      },
      body: JSON.stringify({
        type: "disconnect_user",
        userId: input.userId,
        instanceId: input.instanceId,
        reason: "instance_access_revoked",
      }),
      signal: controller.signal,
    }).finally(() => clearTimeout(timer));
    if (!response.ok) {
      console.warn(`[relay-control] publishGrantRevocation failed status=${response.status}`);
    }
    return response.ok;
  } catch (err) {
    console.warn(
      `[relay-control] publishGrantRevocation failed: ${
        err instanceof Error ? err.message : "unknown"
      }`,
    );
    return false;
  }
}

export async function recordInstanceAuditEvent(input: {
  instanceId: string;
  actorUserId?: string | null;
  clientEventId?: string | null;
  kind: string;
  metadata: unknown;
}) {
  return prisma.instanceAuditEvent.create({
    data: {
      instanceId: input.instanceId,
      actorUserId: input.actorUserId ?? null,
      clientEventId: input.clientEventId ?? null,
      kind: input.kind,
      metadataJson: JSON.stringify(input.metadata),
    },
  });
}

export async function expireStaleInstanceAccessGrants(now = new Date()) {
  await prisma.instanceAccessGrant.updateMany({
    where: {
      status: { in: ["PENDING", "ACTIVE"] },
      expiresAt: { not: null, lte: now },
    },
    data: { status: "EXPIRED" },
  });
}

export function serializeGrant(row: GrantRow) {
  return {
    id: row.id,
    instanceId: row.instanceId,
    ownerId: row.ownerId,
    granteeUserId: row.granteeUserId,
    granteeEmail: row.granteeEmail,
    scope: fromDbScope(row.scope),
    projectRoot: row.projectRoot,
    status: String(row.status).toLowerCase(),
    invitedAt: row.invitedAt,
    acceptedAt: row.acceptedAt,
    revokedAt: row.revokedAt,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export function relayGrantsFromRows(rows: Array<{ scope: unknown; projectRoot: string | null }>) {
  const grants = new Map<string, RelayGrant>();
  for (const row of rows) {
    const scope = fromDbScope(row.scope) as RelayGrantScope;
    const grant = { scope, projectRoot: row.projectRoot ?? null } satisfies RelayGrant;
    grants.set(grant.scope + ":" + (grant.projectRoot ?? "*"), grant);
  }
  return [...grants.values()];
}

export async function activeSharedRelayGrantsForUser(input: {
  instanceId: string;
  userId: string;
  scopes: SharingScope[];
  now?: Date;
}) {
  const now = input.now ?? new Date();
  await expireStaleInstanceAccessGrants(now);
  const rows = await prisma.instanceAccessGrant.findMany({
    where: {
      instanceId: input.instanceId,
      granteeUserId: input.userId,
      status: "ACTIVE",
      scope: { in: input.scopes.map(toDbScope) },
      OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
    },
    orderBy: [{ scope: "asc" }, { projectRootKey: "asc" }],
  });
  return relayGrantsFromRows(rows);
}

export async function requireActiveInstanceForAccess(instanceId: string) {
  const instance = await prisma.cockpitInstance.findUnique({ where: { id: instanceId } });
  if (!instance) throw new ORPCError("NOT_FOUND", { message: "Instance not found." });
  if (String(instance.status) !== "ACTIVE" || instance.revokedAt) {
    throw new ORPCError("FORBIDDEN", { message: "This instance has been revoked." });
  }
  return instance;
}

const remoteAuditEventSchema = z
  .object({
    id: z.string().trim().min(1).max(160).optional(),
    eventId: z.string().trim().min(1).max(160).optional(),
    clientEventId: z.string().trim().min(1).max(160).optional(),
    kind: z.string().trim().min(1).max(120),
    occurredAt: z.string().datetime().optional(),
    actorUserId: z.string().trim().min(1).max(128).optional(),
    principalTag: z.string().trim().min(1).max(256).optional(),
    sessionId: z.string().trim().min(1).max(256).optional(),
    projectRoot: z.string().trim().min(1).max(4096).optional(),
    metadata: z.unknown().optional(),
  })
  .strict()
  .refine((event) => event.clientEventId || event.eventId || event.id, {
    message: "Remote audit events require a client event id.",
  });

export const remoteAuditIngestSchema = z
  .object({
    instanceId: z.string().trim().min(1).max(128),
    instanceToken: z.string().trim().min(1),
    events: z.array(remoteAuditEventSchema).min(1).max(100),
  })
  .strict();

function clientEventIdFor(event: z.infer<typeof remoteAuditEventSchema>) {
  return event.clientEventId ?? event.eventId ?? event.id ?? "";
}

async function requireActiveInstanceForToken(instanceId: string, instanceToken: string) {
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

export async function ingestRemoteInstanceAuditEvents(body: unknown) {
  const parsed = remoteAuditIngestSchema.parse(body);
  const instance = await requireActiveInstanceForToken(parsed.instanceId, parsed.instanceToken);
  const data = parsed.events.map((event) => ({
    instanceId: instance.id,
    actorUserId: null,
    clientEventId: clientEventIdFor(event),
    kind: event.kind,
    metadataJson: JSON.stringify({
      occurredAt: event.occurredAt ?? null,
      actorUserId: event.actorUserId ?? null,
      principalTag: event.principalTag ?? null,
      sessionId: event.sessionId ?? null,
      projectRoot: event.projectRoot ?? null,
      metadata: event.metadata ?? null,
    }),
  }));

  const result = await prisma.instanceAuditEvent.createMany({
    data,
    skipDuplicates: true,
  });
  return { received: data.length, ingested: result.count };
}

export async function revokeInstanceAccessGrantsForDeletedUser(input: {
  userId: string;
  actorUserId?: string | null;
}) {
  const grants = await prisma.instanceAccessGrant.findMany({
    where: {
      granteeUserId: input.userId,
      status: { in: ["PENDING", "ACTIVE", "EXPIRED"] },
    },
    select: { id: true, instanceId: true, status: true, scope: true, projectRoot: true },
  });
  if (grants.length === 0) return { revokedCount: 0, disconnectsSent: 0 };

  const revokedAt = new Date();
  await prisma.instanceAccessGrant.updateMany({
    where: { id: { in: grants.map((grant) => grant.id) } },
    data: { status: "REVOKED", revokedAt },
  });

  let disconnectsSent = 0;
  const disconnectSentByInstance = new Map<string, boolean>();
  for (const instanceId of new Set(grants.map((grant) => grant.instanceId))) {
    const sent = await publishGrantRevocation({ userId: input.userId, instanceId });
    disconnectSentByInstance.set(instanceId, sent);
    if (sent) disconnectsSent += 1;
  }

  await Promise.all(
    grants.map((grant) =>
      recordInstanceAuditEvent({
        instanceId: grant.instanceId,
        actorUserId: input.actorUserId ?? null,
        kind: "grant_revoked_account_deleted",
        metadata: {
          grantId: grant.id,
          granteeUserId: input.userId,
          previousStatus: String(grant.status).toLowerCase(),
          scope: fromDbScope(grant.scope),
          projectRoot: grant.projectRoot,
          disconnectSent: disconnectSentByInstance.get(grant.instanceId) ?? false,
        },
      }),
    ),
  );

  return { revokedCount: grants.length, disconnectsSent };
}
