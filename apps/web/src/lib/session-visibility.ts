import type { SessionSummary } from "@flycockpit/cockpit-protocol";

export type SharingGrant = {
  scope: string;
  projectRoot: string | null;
};

export type SharedInstanceAccess = {
  instance: { id: string };
  grants: SharingGrant[];
};

export type SessionViewerMode = "owner" | "agent" | "agent_readonly" | "none";

export function grantMatchesProject(grant: SharingGrant, projectRoot: string) {
  return grant.projectRoot === null || grant.projectRoot === projectRoot;
}

export function resolveSessionViewerMode(input: {
  instanceId: string;
  projectRoot: string;
  ownedInstanceIds: string[];
  sharedInstances: SharedInstanceAccess[];
}): SessionViewerMode {
  if (input.ownedInstanceIds.includes(input.instanceId)) return "owner";
  const shared = input.sharedInstances.find((item) => item.instance.id === input.instanceId);
  if (!shared) return "none";
  const matching = shared.grants.filter((grant) => grantMatchesProject(grant, input.projectRoot));
  if (matching.some((grant) => grant.scope === "agent")) return "agent";
  if (matching.some((grant) => grant.scope === "agent_readonly")) return "agent_readonly";
  return "none";
}

export function canMutateSessions(mode: SessionViewerMode) {
  return mode === "owner" || mode === "agent";
}

export function shouldShowSessionAttribution(input: {
  session: SessionSummary;
  viewerMode: SessionViewerMode;
  viewerUserId?: string;
}) {
  const creatorUserId = input.session.createdBy?.userId;
  return Boolean(
    input.viewerMode === "owner" && creatorUserId && creatorUserId !== input.viewerUserId,
  );
}

export function sessionAttributionName(session: SessionSummary, fallback: string) {
  return session.createdBy?.displayName ?? session.createdBy?.userId ?? fallback;
}
