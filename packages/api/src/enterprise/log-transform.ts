import type {
  EnterpriseEventKind,
  EnterpriseExportFilters,
  EnterpriseLogExportFormat,
} from "./contracts";

export type EnterpriseLogEventForExport = {
  id: string;
  orgId: string;
  userId: string;
  instanceId: string;
  seq: number;
  sessionId: string;
  projectRoot: string | null;
  kind: EnterpriseEventKind;
  occurredAt: Date | null;
  model: string | null;
  role: string | null;
  content: string | null;
  payload: unknown;
  redactionVersion: string;
  truncated: boolean;
};

export type EnterpriseExportManifest = {
  eventCount: number;
  sessionCount: number;
  userCount: number;
  instanceCount: number;
  byKind: Record<EnterpriseEventKind, number>;
  partialSessionCount: number;
  filters: EnterpriseExportFilters;
};

export type EnterpriseArtifact = {
  body: string;
  contentType: string;
  manifest: EnterpriseExportManifest;
};

const EMPTY_KIND_COUNTS: Record<EnterpriseEventKind, number> = {
  SESSION: 0,
  MESSAGE: 0,
  TOOL_CALL: 0,
  TOOL_RESULT: 0,
  INFERENCE: 0,
  TRUNCATION: 0,
};

export function buildEnterpriseExportArtifact(
  events: EnterpriseLogEventForExport[],
  format: EnterpriseLogExportFormat,
  filters: EnterpriseExportFilters,
): EnterpriseArtifact {
  const ordered = [...events].sort((a, b) =>
    a.sessionId === b.sessionId ? a.seq - b.seq : a.sessionId.localeCompare(b.sessionId),
  );
  const manifest = buildManifest(ordered, filters);
  return {
    body: format === "RAW_NDJSON" ? toRawNdjson(ordered) : toChatJsonl(ordered),
    contentType: "application/x-ndjson; charset=utf-8",
    manifest,
  };
}

export function buildManifest(
  events: EnterpriseLogEventForExport[],
  filters: EnterpriseExportFilters,
): EnterpriseExportManifest {
  const byKind = { ...EMPTY_KIND_COUNTS };
  const sessions = new Set<string>();
  const users = new Set<string>();
  const instances = new Set<string>();
  const partialSessions = new Set<string>();
  for (const event of events) {
    byKind[event.kind] += 1;
    sessions.add(event.sessionId);
    users.add(event.userId);
    instances.add(event.instanceId);
    if (event.truncated || event.kind === "TRUNCATION") partialSessions.add(event.sessionId);
  }
  return {
    eventCount: events.length,
    sessionCount: sessions.size,
    userCount: users.size,
    instanceCount: instances.size,
    byKind,
    partialSessionCount: partialSessions.size,
    filters,
  };
}

function toRawNdjson(events: EnterpriseLogEventForExport[]) {
  return (
    events.map((event) => JSON.stringify(serializeEvent(event))).join("\n") +
    (events.length ? "\n" : "")
  );
}

function toChatJsonl(events: EnterpriseLogEventForExport[]) {
  const grouped = new Map<string, EnterpriseLogEventForExport[]>();
  for (const event of events) {
    const list = grouped.get(event.sessionId) ?? [];
    list.push(event);
    grouped.set(event.sessionId, list);
  }

  return (
    [...grouped.entries()]
      .map(([sessionId, sessionEvents]) => {
        const ordered = sessionEvents.sort((a, b) => a.seq - b.seq);
        return JSON.stringify({
          messages: ordered.flatMap(eventToChatMessages),
          metadata: {
            sessionId,
            userIds: [...new Set(ordered.map((event) => event.userId))],
            instanceIds: [...new Set(ordered.map((event) => event.instanceId))],
            projectRoots: [...new Set(ordered.map((event) => event.projectRoot).filter(Boolean))],
            models: [...new Set(ordered.map((event) => event.model).filter(Boolean))],
            eventCount: ordered.length,
            truncated: ordered.some((event) => event.truncated || event.kind === "TRUNCATION"),
          },
        });
      })
      .join("\n") + (grouped.size ? "\n" : "")
  );
}

function eventToChatMessages(event: EnterpriseLogEventForExport): Array<Record<string, unknown>> {
  if (event.kind === "MESSAGE") {
    return [
      {
        role: normalRole(event.role),
        content: event.content ?? payloadString(event.payload, "content") ?? "",
      },
    ];
  }
  if (event.kind === "TOOL_CALL") {
    return [
      {
        role: "assistant",
        tool_calls: [
          {
            id: payloadString(event.payload, "callId") ?? "tool-" + event.seq,
            type: "function",
            function: {
              name: payloadString(event.payload, "toolName") ?? "tool",
              arguments: JSON.stringify(payloadValue(event.payload, "args") ?? {}),
            },
          },
        ],
      },
    ];
  }
  if (event.kind === "TOOL_RESULT") {
    return [
      {
        role: "tool",
        tool_call_id: payloadString(event.payload, "callId") ?? "tool-" + event.seq,
        content: event.content ?? payloadString(event.payload, "content") ?? "",
      },
    ];
  }
  if (event.kind === "TRUNCATION" || event.truncated) {
    return [{ role: "system", content: "[truncated session data omitted]" }];
  }
  return [];
}

function serializeEvent(event: EnterpriseLogEventForExport) {
  return {
    id: event.id,
    orgId: event.orgId,
    userId: event.userId,
    instanceId: event.instanceId,
    seq: event.seq,
    sessionId: event.sessionId,
    projectRoot: event.projectRoot,
    kind: event.kind,
    occurredAt: event.occurredAt?.toISOString() ?? null,
    model: event.model,
    role: event.role,
    content: event.content,
    payload: event.payload,
    redactionVersion: event.redactionVersion,
    truncated: event.truncated,
  };
}

function normalRole(role: string | null) {
  if (role === "system" || role === "assistant" || role === "tool") return role;
  return "user";
}

function payloadString(payload: unknown, key: string) {
  const value = payloadValue(payload, key);
  return typeof value === "string" ? value : null;
}

function payloadValue(payload: unknown, key: string): unknown {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return undefined;
  return (payload as Record<string, unknown>)[key];
}
