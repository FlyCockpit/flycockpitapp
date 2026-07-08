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
const { deviceAdminGate } = await import("./device-admin-gate");

const db = prisma as unknown as {
  appSetting: { findMany: ReturnType<typeof vi.fn> };
  deviceCode: { findUnique: ReturnType<typeof vi.fn> };
};

describe("deviceAdminGate", () => {
  let app: Hono;
  const downstream = vi.fn((c: Context) => c.json({ ok: true }));

  beforeEach(() => {
    getSession.mockReset();
    db.appSetting.findMany.mockResolvedValue([]);
    db.deviceCode.findUnique.mockResolvedValue({ clientId: "admin-mcp" });
    downstream.mockClear();
    app = new Hono();
    app.use("/api/auth/device/approve", deviceAdminGate);
    app.use("/api/auth/device/deny", deviceAdminGate);
    app.all("/api/auth/device/approve", downstream);
    app.all("/api/auth/device/deny", downstream);
  });

  it("rejects unauthenticated callers with 401", async () => {
    getSession.mockResolvedValue(null);
    const res = await app.request("/api/auth/device/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userCode: "ABC123" }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({
      error: "unauthorized",
      error_description: "Authentication required",
    });
    expect(downstream).not.toHaveBeenCalled();
  });

  it("keeps non-cockpit-cli device codes admin-only", async () => {
    getSession.mockResolvedValue({ user: { id: "u1", role: "user", emailVerified: true } });
    const res = await app.request("/api/auth/device/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userCode: "ADMIN123" }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: "access_denied",
      error_description: "Verified admin access required",
    });
    expect(downstream).not.toHaveBeenCalled();
  });

  it("allows verified non-admin users to approve cockpit-cli device codes", async () => {
    db.deviceCode.findUnique.mockResolvedValue({ clientId: "cockpit-cli" });
    getSession.mockResolvedValue({
      user: { id: "u1", role: "user", emailVerified: true, twoFactorEnabled: false },
    });
    const res = await app.request("/api/auth/device/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userCode: "CLI123" }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(downstream).toHaveBeenCalledTimes(1);
  });

  it("accepts snake_case user_code from raw device clients", async () => {
    db.deviceCode.findUnique.mockResolvedValue({ clientId: "cockpit-cli" });
    getSession.mockResolvedValue({ user: { id: "u1", role: "user", emailVerified: true } });
    const res = await app.request("/api/auth/device/deny", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_code: "CLI123" }),
    });
    expect(res.status).toBe(200);
    expect(downstream).toHaveBeenCalledTimes(1);
  });

  it("rejects unverified cockpit-cli approvers", async () => {
    db.deviceCode.findUnique.mockResolvedValue({ clientId: "cockpit-cli" });
    getSession.mockResolvedValue({ user: { id: "u1", role: "user", emailVerified: false } });
    const res = await app.request("/api/auth/device/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userCode: "CLI123" }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: "access_denied",
      error_description: "Verified account required",
    });
    expect(downstream).not.toHaveBeenCalled();
  });

  it("still admits an admin caller for admin device flows", async () => {
    getSession.mockResolvedValue({ user: { id: "admin-1", role: "admin", emailVerified: true } });
    const res = await app.request("/api/auth/device/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userCode: "ADMIN123" }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(downstream).toHaveBeenCalledTimes(1);
  });

  it("rejects admins without 2FA when admin 2FA is required", async () => {
    getSession.mockResolvedValue({
      user: { id: "admin-1", role: "admin", emailVerified: true, twoFactorEnabled: false },
    });
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "true" }]);
    const res = await app.request("/api/auth/device/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userCode: "ADMIN123" }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: "access_denied",
      error_description: "Two-factor authentication setup is required",
    });
    expect(downstream).not.toHaveBeenCalled();
  });
});
