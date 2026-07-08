import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

// We mock @flycockpit/auth at the module boundary so the auth middleware reads
// session resolution from a stub instead of touching the real Better-Auth
// instance (which would otherwise try to connect to Postgres on import).
const getSession = vi.fn();
const apiKeyFindUnique = vi.fn();

vi.mock("@flycockpit/auth", () => ({
  auth: {
    api: {
      get getSession() {
        return getSession;
      },
    },
  },
}));

vi.mock("@flycockpit/db", () => ({
  default: {
    apiKey: {
      findFirst: apiKeyFindUnique,
    },
  },
}));

const { mcpAuthMiddleware, mcpContextStorage } = await import("./auth");

describe("mcpAuthMiddleware", () => {
  let app: Hono;

  beforeEach(() => {
    getSession.mockReset();
    apiKeyFindUnique.mockReset();
    apiKeyFindUnique.mockResolvedValue(null);
    app = new Hono();
    app.all("/mcp", mcpAuthMiddleware, (c) => {
      const store = mcpContextStorage.getStore();
      return c.json({ ok: true, userId: store?.session.user.id ?? null });
    });
  });

  it("returns body-less 401 when no Authorization header is sent", async () => {
    // Even if Better-Auth would resolve some session, the wrapper must
    // short-circuit before consulting it — `/mcp` is bearer-only.
    getSession.mockResolvedValue({ user: { id: "admin-1", role: "admin" } });
    const res = await app.request("/mcp", { method: "POST" });
    expect(res.status).toBe(401);
    expect(await res.text()).toBe("");
    expect(getSession).not.toHaveBeenCalled();
  });

  it("returns body-less 401 when only a session cookie is sent (no Bearer header)", async () => {
    // Cookie-only requests must not authenticate `/mcp`. The CSRF posture
    // documented in the MCP auth contract depends on cookies being ignored
    // here; if Better-Auth is given the cookie it would happily admit it.
    getSession.mockResolvedValue({ user: { id: "admin-1", role: "admin" } });
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { Cookie: "better-auth.session_token=valid-cookie" },
    });
    expect(res.status).toBe(401);
    expect(await res.text()).toBe("");
    expect(getSession).not.toHaveBeenCalled();
  });

  it("returns body-less 401 for a non-Bearer Authorization scheme", async () => {
    getSession.mockResolvedValue({ user: { id: "admin-1", role: "admin" } });
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { Authorization: "Basic dXNlcjpwYXNz" },
    });
    expect(res.status).toBe(401);
    expect(await res.text()).toBe("");
    expect(getSession).not.toHaveBeenCalled();
  });

  it("returns body-less 401 for a token whose user is not admin", async () => {
    getSession.mockResolvedValue({ user: { id: "u1", role: "user" } });
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer some-key" },
    });
    expect(res.status).toBe(401);
    expect(await res.text()).toBe("");
  });

  it("returns body-less 401 for an unverified admin token", async () => {
    getSession.mockResolvedValue({
      user: { id: "admin-1", role: "admin", emailVerified: false },
    });
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer pending-admin" },
    });
    expect(res.status).toBe(401);
    expect(await res.text()).toBe("");
  });

  it("returns body-less 401 when getSession throws", async () => {
    getSession.mockRejectedValue(new Error("boom"));
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer broken" },
    });
    expect(res.status).toBe(401);
    expect(await res.text()).toBe("");
  });

  it("admits an admin session and exposes it via mcpContextStorage", async () => {
    getSession.mockResolvedValue({
      user: { id: "admin-1", role: "admin", emailVerified: true },
    });
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer good-key" },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, userId: "admin-1" });
  });

  it("admits a verified session whose comma-separated role list contains admin", async () => {
    getSession.mockResolvedValue({
      user: { id: "admin-1", role: "editor,admin", emailVerified: true },
    });
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer good-key" },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, userId: "admin-1" });
  });

  it("strips cookies from headers passed to getSession when a Bearer is present", async () => {
    getSession.mockResolvedValue({ user: { id: "admin-1", role: "admin" } });
    await app.request("/mcp", {
      method: "POST",
      headers: {
        Authorization: "Bearer good-key",
        Cookie: "better-auth.session_token=should-be-ignored",
      },
    });
    expect(getSession).toHaveBeenCalledTimes(1);
    const passed = getSession.mock.calls[0]?.[0]?.headers as Headers;
    expect(passed.get("authorization")).toBe("Bearer good-key");
    expect(passed.get("cookie")).toBeNull();
  });
});
