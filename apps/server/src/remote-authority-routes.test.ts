import {
  AuthorityPublicSnapshot,
  REMOTE_AUTHORITY_JWKS_MAX_AGE_SECONDS,
} from "@flycockpit/api/lib/remote-authority";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { mountRemoteAuthorityRoutes } from "./remote-authority-routes";

function appAt(now: string, snapshot = new AuthorityPublicSnapshot()) {
  const app = new Hono();
  mountRemoteAuthorityRoutes(app, { snapshot, now: () => now });
  return { app, snapshot };
}

describe("remote_authority_jwks_and_status_public_only", () => {
  it("serves deterministic bytes, strong ETags, exact cache headers and 304 responses", async () => {
    const { app, snapshot } = appAt("100");
    snapshot.publish(
      { keys: [{ alg: "ES256", crv: "P-256", kid: "k0", kty: "EC", use: "sig", x: "x", y: "y" }] },
      "header.payload.signature",
      "160",
      "100",
    );
    const jwks = await app.request("/api/remote/jwks.json"),
      jwksBody = await jwks.text(),
      etag = jwks.headers.get("etag")!;
    expect(jwks.status).toBe(200);
    expect(jwks.headers.get("cache-control")).toBe(
      `public, max-age=${REMOTE_AUTHORITY_JWKS_MAX_AGE_SECONDS}, must-revalidate`,
    );
    expect(jwks.headers.get("vary")).toBe("Accept-Encoding");
    expect(etag).toMatch(/^"[0-9a-f]{64}"$/);
    expect(jwksBody).not.toContain('"d"');
    const unchanged = await app.request("/api/remote/jwks.json", {
      headers: { "if-none-match": etag },
    });
    expect(unchanged.status).toBe(304);
    expect(await unchanged.text()).toBe("");
    const status = await app.request("/api/remote/authority-status.json");
    expect(status.headers.get("cache-control")).toBe("no-store");
    expect(status.headers.get("content-type")).toContain("application/jose");
    expect(await status.text()).toBe("header.payload.signature");
  });

  it("returns unavailable without leaking stale or private material", async () => {
    const { app } = appAt("161");
    const response = await app.request("/api/remote/jwks.json");
    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({ error: "remote authority unavailable" });
  });
});
