import { type Context, Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

const getSession = vi.fn();

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep<typeof import("@flycockpit/db").default>();
  db.appSetting.findMany.mockResolvedValue([]);
  return { default: db };
});

vi.mock("@flycockpit/auth", () => ({
  auth: {
    api: {
      get getSession() {
        return getSession;
      },
    },
  },
}));

const { default: prisma } = await import("@flycockpit/db");
const { apiKeyAdminGate } = await import("./api-key-admin-gate");

const db = prisma as unknown as {
  appSetting: { findMany: ReturnType<typeof vi.fn> };
};

describe("apiKeyAdminGate", () => {
  let app: Hono;
  const downstream = vi.fn((c: Context) => c.json({ ok: true }));

  beforeEach(() => {
    getSession.mockReset();
    db.appSetting.findMany.mockResolvedValue([]);
    downstream.mockClear();
    app = new Hono();
    app.use("/api/auth/api-key/list", apiKeyAdminGate);
    app.all("/api/auth/api-key/list", downstream);
  });

  it("rejects unauthenticated callers with 401", async () => {
    getSession.mockResolvedValue(null);
    const res = await app.request("/api/auth/api-key/list", { method: "GET" });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({
      error: "unauthorized",
      error_description: "Authentication required",
    });
    expect(downstream).not.toHaveBeenCalled();
  });

  it("rejects non-admin callers with 403", async () => {
    getSession.mockResolvedValue({ user: { id: "u1", role: "user", emailVerified: true } });
    const res = await app.request("/api/auth/api-key/list", { method: "GET" });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: "access_denied",
      error_description: "Verified admin access required",
    });
    expect(downstream).not.toHaveBeenCalled();
  });

  it("rejects unverified admins with 403", async () => {
    getSession.mockResolvedValue({ user: { id: "a1", role: "admin", emailVerified: false } });
    const res = await app.request("/api/auth/api-key/list", { method: "GET" });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: "access_denied",
      error_description: "Verified admin access required",
    });
    expect(downstream).not.toHaveBeenCalled();
  });

  it("admits verified comma-separated admin roles", async () => {
    getSession.mockResolvedValue({
      user: { id: "a1", role: "editor, admin", emailVerified: true },
    });
    const res = await app.request("/api/auth/api-key/list", { method: "GET" });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(downstream).toHaveBeenCalledTimes(1);
  });

  it("rejects admins without 2FA when admin 2FA is required", async () => {
    getSession.mockResolvedValue({
      user: { id: "a1", role: "admin", emailVerified: true, twoFactorEnabled: false },
    });
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "true" }]);
    const res = await app.request("/api/auth/api-key/list", { method: "GET" });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: "access_denied",
      error_description: "Two-factor authentication setup is required",
    });
    expect(downstream).not.toHaveBeenCalled();
  });
});
