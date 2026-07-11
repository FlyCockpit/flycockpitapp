import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

const getSession = vi.fn();

vi.mock("@flycockpit/auth", () => ({
  auth: {
    api: {
      get getSession() {
        return getSession;
      },
    },
  },
}));

const { sessionMiddleware } = await import("./session-middleware");

function lastHeaders(): Headers {
  const call = getSession.mock.calls.at(-1);
  return (call?.[0] as { headers: Headers }).headers;
}

describe("sessionMiddleware", () => {
  let app: Hono;

  beforeEach(() => {
    getSession.mockReset();
    getSession.mockResolvedValue(null);

    app = new Hono();
    app.use("*", sessionMiddleware);
    app.get("/", (c) => c.json({ session: c.get("session" as never) ?? null }));
  });

  it("does not forward the Authorization header to getSession", async () => {
    await app.request("/", {
      headers: { authorization: "Bearer some-api-key" },
    });

    expect(getSession).toHaveBeenCalledTimes(1);
    expect(lastHeaders().get("authorization")).toBeNull();
  });

  it("strips Authorization regardless of header casing", async () => {
    await app.request("/", {
      headers: { AuThOrIzAtIoN: "bEaReR some-api-key" },
    });

    expect(lastHeaders().get("authorization")).toBeNull();
  });

  it("still forwards cookies", async () => {
    await app.request("/", {
      headers: {
        authorization: "Bearer some-api-key",
        cookie: "better-auth.session_token=abc",
      },
    });

    const headers = lastHeaders();
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("cookie")).toBe("better-auth.session_token=abc");
  });

  it("resolves a cookie session onto the context", async () => {
    const session = { user: { id: "u1" } };
    getSession.mockResolvedValue(session);

    const res = await app.request("/", {
      headers: { cookie: "better-auth.session_token=abc" },
    });

    expect(await res.json()).toEqual({ session });
  });

  it("treats a getSession failure as anonymous rather than a 500", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    getSession.mockRejectedValue(new Error("db down"));

    const res = await app.request("/");

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ session: null });
  });
});
