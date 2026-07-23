import { describe, expect, it } from "vitest";
import type { WebSessionSummary } from "@/stores/remote-sessions";
import {
  canMutateSessions,
  resolveSessionViewerMode,
  sessionAttributionName,
  shouldShowSessionAttribution,
} from "./session-visibility";

const session = (createdBy: WebSessionSummary["createdBy"]): WebSessionSummary => ({
  sessionId: "11111111-1111-4111-8111-111111111111",
  projectId: "repo",
  projectRoot: "/repo",
  title: "Fix checkout",
  status: "idle",
  archived: false,
  pinned: false,
  forkCount: 0,
  turnCount: 0,
  attention: null,
  updatedAt: 1783296000,
  createdBy,
  agent: "Build",
  sharedWithCollaborators: false,
});

describe("session visibility UX state", () => {
  it("renders attribution only for owner views of non-owner sessions", () => {
    const granteeSession = session({ userId: "grantee-1", displayName: "Ada" });
    expect(
      shouldShowSessionAttribution({
        session: granteeSession,
        viewerMode: "owner",
        viewerUserId: "owner-1",
      }),
    ).toBe(true);
    expect(sessionAttributionName(granteeSession, "Collaborator")).toBe("Ada");
    expect(
      shouldShowSessionAttribution({
        session: session(null),
        viewerMode: "owner",
        viewerUserId: "owner-1",
      }),
    ).toBe(false);
    expect(
      shouldShowSessionAttribution({
        session: granteeSession,
        viewerMode: "agent",
        viewerUserId: "grantee-1",
      }),
    ).toBe(false);
  });

  it("resolves owner, read-write grantee, and read-only grantee modes by project grant", () => {
    expect(
      resolveSessionViewerMode({
        instanceId: "i1",
        projectRoot: "/repo",
        ownedInstanceIds: ["i1"],
        sharedInstances: [],
      }),
    ).toBe("owner");
    expect(
      resolveSessionViewerMode({
        instanceId: "i1",
        projectRoot: "/repo",
        ownedInstanceIds: [],
        sharedInstances: [
          { instance: { id: "i1" }, grants: [{ scope: "agent", projectRoot: "/repo" }] },
        ],
      }),
    ).toBe("agent");
    expect(
      resolveSessionViewerMode({
        instanceId: "i1",
        projectRoot: "/repo",
        ownedInstanceIds: [],
        sharedInstances: [
          {
            instance: { id: "i1" },
            grants: [{ scope: "agent_readonly", projectRoot: null }],
          },
        ],
      }),
    ).toBe("agent_readonly");
    expect(canMutateSessions("agent_readonly")).toBe(false);
    expect(canMutateSessions("agent")).toBe(true);
  });
});
