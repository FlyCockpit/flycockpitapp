import type { Session } from "@flycockpit/auth";
import { createRouterClient, ORPCError } from "@orpc/server";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep();
  db.appSetting.findMany.mockResolvedValue([]);
  return { default: db };
});

// `adminProcedure` imports from @flycockpit/env/server, which validates
// `process.env` at import time. Mock the module so this test doesn't need a
// real .env at resolve time.
vi.mock("@flycockpit/env/server", () => ({
  env: {},
}));

import type { Context } from "./context";
import { adminOr404Procedure, adminProcedure, protectedProcedure } from "./index";

const { default: prisma } = await import("@flycockpit/db");

const db = prisma as unknown as {
  appSetting: {
    findMany: MockInstance;
  };
};

/**
 * Minimal router that uses adminProcedure so we can exercise the middleware
 * chain (requireAuth → requireAdmin) in isolation.
 */
const testRouter = {
  ping: adminProcedure.handler(async () => {
    return { ok: true };
  }),
};

const protectedRouter = {
  ping: protectedProcedure.handler(async () => {
    return { ok: true };
  }),
};

const testRouter404 = {
  ping: adminOr404Procedure.handler(async () => {
    return { ok: true };
  }),
};

/** Build a minimal oRPC context for testing. */
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

beforeEach(() => {
  vi.clearAllMocks();
  db.appSetting.findMany.mockResolvedValue([]);
});

describe("protectedProcedure", () => {
  it("throws FORBIDDEN when public-user 2FA is required and the user has no second factor", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faPublicUsers", value: "true" }]);
    const ctx = buildContext({ user: { twoFactorEnabled: false } });
    const client = createRouterClient(protectedRouter, { context: ctx });

    await expect(client.ping()).rejects.toSatisfy((error: ORPCError) => {
      expect(error).toBeInstanceOf(ORPCError);
      expect(error.code).toBe("FORBIDDEN");
      expect(error.message).toMatch(/Two-factor authentication setup is required/);
      return true;
    });
  });

  it("passes through when public-user 2FA is required and the user has a second factor", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faPublicUsers", value: "true" }]);
    const ctx = buildContext({ user: { twoFactorEnabled: true } });
    const client = createRouterClient(protectedRouter, { context: ctx });

    await expect(client.ping()).resolves.toEqual({ ok: true });
  });

  it("falls back to the legacy force2fa setting when role-scoped settings do not exist", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2fa", value: "true" }]);
    const ctx = buildContext({ user: { twoFactorEnabled: false } });
    const client = createRouterClient(protectedRouter, { context: ctx });

    await expect(client.ping()).rejects.toSatisfy((error: ORPCError) => {
      expect(error).toBeInstanceOf(ORPCError);
      expect(error.code).toBe("FORBIDDEN");
      return true;
    });
  });
});

describe("adminProcedure", () => {
  it("throws FORBIDDEN with 'Email verification required' when emailVerified is false", async () => {
    const ctx = buildContext({ user: { role: "admin", emailVerified: false } });
    const client = createRouterClient(testRouter, { context: ctx });

    await expect(client.ping()).rejects.toSatisfy((error: ORPCError) => {
      expect(error).toBeInstanceOf(ORPCError);
      expect(error.code).toBe("FORBIDDEN");
      expect(error.message).toBe("Email verification required for admin access.");
      return true;
    });
  });

  it("throws FORBIDDEN with 'Admin access required' when role is not admin", async () => {
    const ctx = buildContext({ user: { role: "user", emailVerified: true } });
    const client = createRouterClient(testRouter, { context: ctx });

    await expect(client.ping()).rejects.toSatisfy((error: ORPCError) => {
      expect(error).toBeInstanceOf(ORPCError);
      expect(error.code).toBe("FORBIDDEN");
      expect(error.message).toBe("Admin access required.");
      return true;
    });
  });

  it("passes through to the handler for a verified admin", async () => {
    const ctx = buildContext({ user: { role: "admin", emailVerified: true } });
    const client = createRouterClient(testRouter, { context: ctx });

    const result = await client.ping();

    expect(result).toEqual({ ok: true });
  });

  it("throws FORBIDDEN when admin 2FA is required and the admin has no second factor", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "true" }]);
    const ctx = buildContext({
      user: { role: "admin", emailVerified: true, twoFactorEnabled: false },
    });
    const client = createRouterClient(testRouter, { context: ctx });

    await expect(client.ping()).rejects.toSatisfy((error: ORPCError) => {
      expect(error).toBeInstanceOf(ORPCError);
      expect(error.code).toBe("FORBIDDEN");
      expect(error.message).toMatch(/Two-factor authentication setup is required/);
      return true;
    });
  });

  it("does not apply the public-user 2FA setting to admins", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faPublicUsers", value: "true" }]);
    const ctx = buildContext({
      user: { role: "admin", emailVerified: true, twoFactorEnabled: false },
    });
    const client = createRouterClient(testRouter, { context: ctx });

    await expect(client.ping()).resolves.toEqual({ ok: true });
  });

  it("passes through to the handler when admin appears in a comma-separated role list", async () => {
    const ctx = buildContext({ user: { role: "editor, admin, billing", emailVerified: true } });
    const client = createRouterClient(testRouter, { context: ctx });

    const result = await client.ping();

    expect(result).toEqual({ ok: true });
  });
});

describe("adminOr404Procedure", () => {
  it("throws NOT_FOUND when no session is provided", async () => {
    const ctx = buildContext(null);
    const client = createRouterClient(testRouter404, { context: ctx });

    await expect(client.ping()).rejects.toSatisfy((error: ORPCError) => {
      expect(error).toBeInstanceOf(ORPCError);
      expect(error.code).toBe("NOT_FOUND");
      expect(error.message).toBe("Not found");
      return true;
    });
  });

  it("throws NOT_FOUND when emailVerified is false", async () => {
    const ctx = buildContext({ user: { role: "admin", emailVerified: false } });
    const client = createRouterClient(testRouter404, { context: ctx });

    await expect(client.ping()).rejects.toSatisfy((error: ORPCError) => {
      expect(error).toBeInstanceOf(ORPCError);
      expect(error.code).toBe("NOT_FOUND");
      expect(error.message).toBe("Not found");
      return true;
    });
  });

  it("throws NOT_FOUND when role is not admin", async () => {
    const ctx = buildContext({ user: { role: "user", emailVerified: true } });
    const client = createRouterClient(testRouter404, { context: ctx });

    await expect(client.ping()).rejects.toSatisfy((error: ORPCError) => {
      expect(error).toBeInstanceOf(ORPCError);
      expect(error.code).toBe("NOT_FOUND");
      expect(error.message).toBe("Not found");
      return true;
    });
  });

  it("passes through to the handler for a verified admin", async () => {
    const ctx = buildContext({ user: { role: "admin", emailVerified: true } });
    const client = createRouterClient(testRouter404, { context: ctx });

    const result = await client.ping();

    expect(result).toEqual({ ok: true });
  });

  it("throws NOT_FOUND when admin 2FA is required and the admin has no second factor", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "true" }]);
    const ctx = buildContext({
      user: { role: "admin", emailVerified: true, twoFactorEnabled: false },
    });
    const client = createRouterClient(testRouter404, { context: ctx });

    await expect(client.ping()).rejects.toSatisfy((error: ORPCError) => {
      expect(error).toBeInstanceOf(ORPCError);
      expect(error.code).toBe("NOT_FOUND");
      expect(error.message).toBe("Not found");
      return true;
    });
  });

  it("passes through to the handler when admin appears in a comma-separated role list", async () => {
    const ctx = buildContext({ user: { role: "editor,admin", emailVerified: true } });
    const client = createRouterClient(testRouter404, { context: ctx });

    const result = await client.ping();

    expect(result).toEqual({ ok: true });
  });
});
