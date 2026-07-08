import { describe, expect, it } from "vitest";
import { buildEnterpriseExportArtifact, type EnterpriseLogEventForExport } from "./log-transform";

const filters = { orgId: "org-1" };
const events: EnterpriseLogEventForExport[] = [
  {
    id: "e1",
    orgId: "org-1",
    userId: "user-1",
    instanceId: "instance-1",
    seq: 1,
    sessionId: "session-1",
    projectRoot: "/repo",
    kind: "MESSAGE",
    occurredAt: new Date("2026-01-01T00:00:00.000Z"),
    model: "gpt-test",
    role: "user",
    content: "inspect the project",
    payload: {},
    redactionVersion: "cli-redaction-v1",
    truncated: false,
  },
  {
    id: "e2",
    orgId: "org-1",
    userId: "user-1",
    instanceId: "instance-1",
    seq: 2,
    sessionId: "session-1",
    projectRoot: "/repo",
    kind: "TOOL_CALL",
    occurredAt: new Date("2026-01-01T00:00:01.000Z"),
    model: "gpt-test",
    role: "assistant",
    content: null,
    payload: { callId: "call-1", toolName: "shell", args: { cmd: "git status" } },
    redactionVersion: "cli-redaction-v1",
    truncated: false,
  },
  {
    id: "e3",
    orgId: "org-1",
    userId: "user-1",
    instanceId: "instance-1",
    seq: 3,
    sessionId: "session-1",
    projectRoot: "/repo",
    kind: "TOOL_RESULT",
    occurredAt: new Date("2026-01-01T00:00:02.000Z"),
    model: "gpt-test",
    role: "tool",
    content: "clean",
    payload: { callId: "call-1" },
    redactionVersion: "cli-redaction-v1",
    truncated: false,
  },
  {
    id: "e4",
    orgId: "org-1",
    userId: "user-2",
    instanceId: "instance-2",
    seq: 1,
    sessionId: "session-2",
    projectRoot: "/repo-2",
    kind: "TRUNCATION",
    occurredAt: new Date("2026-01-02T00:00:00.000Z"),
    model: null,
    role: null,
    content: null,
    payload: {},
    redactionVersion: "cli-redaction-v1",
    truncated: true,
  },
];

describe("buildEnterpriseExportArtifact", () => {
  it("builds a manifest with counts by user, instance, session, and kind", () => {
    const artifact = buildEnterpriseExportArtifact(events, "RAW_NDJSON", filters);

    expect(artifact.manifest).toMatchObject({
      eventCount: 4,
      sessionCount: 2,
      userCount: 2,
      instanceCount: 2,
      partialSessionCount: 1,
      byKind: { MESSAGE: 1, TOOL_CALL: 1, TOOL_RESULT: 1, TRUNCATION: 1 },
    });
    expect(artifact.body.trim().split("\n")).toHaveLength(4);
  });

  it("transforms sessions into chat-format JSONL with tool calls and attribution", () => {
    const artifact = buildEnterpriseExportArtifact(events, "CHAT_JSONL", filters);
    const lines = artifact.body
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));

    expect(lines).toHaveLength(2);
    expect(lines[0].messages).toEqual([
      { role: "user", content: "inspect the project" },
      {
        role: "assistant",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: { name: "shell", arguments: JSON.stringify({ cmd: "git status" }) },
          },
        ],
      },
      { role: "tool", tool_call_id: "call-1", content: "clean" },
    ]);
    expect(lines[0].metadata).toMatchObject({
      sessionId: "session-1",
      userIds: ["user-1"],
      instanceIds: ["instance-1"],
      models: ["gpt-test"],
      truncated: false,
    });
    expect(lines[1].messages).toEqual([
      { role: "system", content: "[truncated session data omitted]" },
    ]);
    expect(lines[1].metadata.truncated).toBe(true);
  });
});
