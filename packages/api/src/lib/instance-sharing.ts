import prisma from "@flycockpit/db";
import { env } from "@flycockpit/env/server";
import { ORPCError } from "@orpc/server";
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

function relayControlUrl() {
  if (!env.COCKPIT_RELAY_URL || !env.RELAY_CONTROL_SECRET) return null;
  const url = new URL(env.COCKPIT_RELAY_URL);
  url.protocol = url.protocol === "wss:" ? "https:" : "http:";
  url.pathname = "/control";
  url.search = "";
  url.hash = "";
  return url.toString();
}

export async function publishGrantRevocation(input: { userId: string; instanceId: string }) {
  const url = relayControlUrl();
  if (!url || !env.RELAY_CONTROL_SECRET) return false;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer " + env.RELAY_CONTROL_SECRET,
      },
      body: JSON.stringify({
        type: "disconnect_user",
        userId: input.userId,
        instanceId: input.instanceId,
        reason: "instance_access_revoked",
      }),
      signal: controller.signal,
    }).finally(() => clearTimeout(timer));
    return response.ok;
  } catch {
    return false;
  }
}

export async function recordInstanceAuditEvent(input: {
  instanceId: string;
  actorUserId?: string | null;
  kind: string;
  metadata: unknown;
}) {
  return prisma.instanceAuditEvent.create({
    data: {
      instanceId: input.instanceId,
      actorUserId: input.actorUserId ?? null,
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
