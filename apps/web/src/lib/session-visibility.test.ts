import type { SessionSummary } from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import {
  canMutateSessions,
  resolveSessionViewerMode,
  sessionAttributionName,
  shouldShowSessionAttribution,
} from "./session-visibility";

const session = (createdBy: SessionSummary["createdBy"]): SessionSummary => ({
  sessionId: "s1",
  projectRoot: "/repo",
  title: "Fix checkout",
  status: "idle",
  archived: false,
  pinned: false,
  forkCount: 0,
  turnCount: 0,
  updatedAt: 1783296000,
  createdBy,
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
