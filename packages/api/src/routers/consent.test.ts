import type { Session } from "@flycockpit/auth";
import prisma from "@flycockpit/db";
import { createRouterClient, ORPCError } from "@orpc/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";
import { consentRouter } from "./consent";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep();
  db.appSetting.findMany.mockResolvedValue([]);
  return { default: db };
});

vi.mock("@flycockpit/env/server", () => ({
  env: {},
}));

function buildContext(
  sessionOverride?: Partial<{
    user: Partial<Session["user"]>;
    session: Partial<Session["session"]>;
  }> | null,
): Context {
  if (sessionOverride === null) return { session: null };

  return {
    session: {
      user: {
        id: "test-user-id",
        email: "test@example.com",
        name: "Test User",
        emailVerified: true,
        role: "user",
        twoFactorEnabled: false,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
        ...sessionOverride?.user,
      },
      session: {
        id: "test-session-id",
        userId: sessionOverride?.user?.id ?? "test-user-id",
        token: "test-token",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: "127.0.0.1",
        userAgent: "vitest",
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
        ...sessionOverride?.session,
      },
    } as Session,
  };
}

const validRecord = {
  anonId: "anon-123",
  policyVersion: 1,
  categories: { functional: true, analytics: false, marketing: false },
  action: "custom" as const,
};

describe("consent router", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ─── record (publicProcedure) ──────────────────────────────────

  describe("record (publicProcedure)", () => {
    it("accepts an anonymous decision and stores userId as null", async () => {
      const ctx = buildContext(null);
      const client = createRouterClient(consentRouter, { context: ctx });

      const result = await client.record(validRecord);

      expect(result).toEqual({ success: true });
      expect(prisma.consentRecord.create).toHaveBeenCalledWith({
        data: expect.objectContaining({ anonId: "anon-123", userId: null, action: "CUSTOM" }),
      });
    });

    it("attributes the decision to the signed-in user from the session, not input", async () => {
      const ctx = buildContext({ user: { id: "real-user" } });
      const client = createRouterClient(consentRouter, { context: ctx });

      await client.record(validRecord);

      expect(prisma.consentRecord.create).toHaveBeenCalledWith({
        data: expect.objectContaining({ userId: "real-user" }),
      });
    });

    it("rejects an invalid action", async () => {
      const ctx = buildContext(null);
      const client = createRouterClient(consentRouter, { context: ctx });

      await expect(
        // @ts-expect-error — exercising the Zod boundary with a bad action
        client.record({ ...validRecord, action: "nope" }),
      ).rejects.toBeInstanceOf(ORPCError);
    });
  });

  // ─── recentRecords (adminOr404Procedure) ───────────────────────

  describe("recentRecords (adminOr404Procedure)", () => {
    it("throws NOT_FOUND when no session is provided", async () => {
      const ctx = buildContext(null);
      const client = createRouterClient(consentRouter, { context: ctx });

      await expect(client.recentRecords({})).rejects.toSatisfy((error: ORPCError) => {
        expect(error).toBeInstanceOf(ORPCError);
        expect(error.code).toBe("NOT_FOUND");
        return true;
      });
    });

    it("throws NOT_FOUND for a non-admin user", async () => {
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(consentRouter, { context: ctx });

      await expect(client.recentRecords({})).rejects.toSatisfy((error: ORPCError) => {
        expect(error.code).toBe("NOT_FOUND");
        return true;
      });
    });

    it("returns a page for an admin", async () => {
      vi.mocked(prisma.consentRecord.findMany).mockResolvedValue([]);
      const ctx = buildContext({ user: { role: "admin", emailVerified: true } });
      const client = createRouterClient(consentRouter, { context: ctx });

      const result = await client.recentRecords({});

      expect(result).toEqual({ items: [], nextCursor: undefined });
    });
  });
});
