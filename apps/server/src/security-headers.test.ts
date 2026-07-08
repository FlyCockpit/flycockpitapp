import { Hono } from "hono";
import { describe, expect, it } from "vitest";

import { mountSecurityHeaders } from "./security-headers";

// Builds an app wired exactly like the real server: mountSecurityHeaders first,
// then the routes underneath it. This is an APP-LEVEL test on purpose — the
// raw-asset `sandbox` CSP only survives because of how mountSecurityHeaders
// orders its two middlewares relative to hono's `secureHeaders`. A handler-only
// test (asserting the header the asset route sets) passes even when the global
// middleware later clobbers it on the wire, which is the bug this guards.
function buildApp() {
  const app = new Hono();
  mountSecurityHeaders(app, {
    cspConnectSrc: ["'self'"],
    themeInitCspHash: "'sha256-test'",
  });
  app.get("/api/assets/:id", (c) => c.text("asset-bytes"));
  app.get("/some-page", (c) => c.text("page"));
  return app;
}

describe("mountSecurityHeaders", () => {
  it("serves /api/assets/:id with the sandbox CSP (not the app policy)", async () => {
    const res = await buildApp().request("/api/assets/abc123");
    expect(res.headers.get("content-security-policy")).toBe("sandbox");
  });

  it("serves non-asset routes with the app CSP, not sandbox", async () => {
    const res = await buildApp().request("/some-page");
    const csp = res.headers.get("content-security-policy");
    expect(csp).not.toBe("sandbox");
    expect(csp).toContain("default-src 'self'");
  });

  it("still applies the app CSP's other security headers to asset responses", async () => {
    // The sandbox override must replace only the CSP, leaving the rest of the
    // secureHeaders battery (e.g. X-Content-Type-Options) intact.
    const res = await buildApp().request("/api/assets/abc123");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  });
});
