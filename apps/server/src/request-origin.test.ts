import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "https://app.example.com",
    CORS_ORIGIN: "https://web.example.com",
  },
}));

const { validateSameSiteJsonRequest } = await import("./request-origin.js");

function makeApp() {
  const app = new Hono();
  app.post("/guarded", (c) => validateSameSiteJsonRequest(c) ?? c.json({ ok: true }));
  return app;
}

describe("validateSameSiteJsonRequest", () => {
  it("allows same-site JSON requests from configured origins", async () => {
    const res = await makeApp().request("/guarded", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://web.example.com",
        "Sec-Fetch-Site": "same-site",
      },
      body: "{}",
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("rejects simple non-JSON requests", async () => {
    const res = await makeApp().request("/guarded", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "{}",
    });

    expect(res.status).toBe(415);
  });

  it("rejects cross-site fetch metadata and unknown origins", async () => {
    const crossSite = await makeApp().request("/guarded", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Sec-Fetch-Site": "cross-site",
      },
      body: "{}",
    });
    expect(crossSite.status).toBe(403);

    const badOrigin = await makeApp().request("/guarded", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://evil.example",
      },
      body: "{}",
    });
    expect(badOrigin.status).toBe(403);
  });
});
