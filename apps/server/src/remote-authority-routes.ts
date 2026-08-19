import {
  type AuthorityPublicSnapshot,
  REMOTE_AUTHORITY_JWKS_MAX_AGE_SECONDS,
} from "@flycockpit/api/lib/remote-authority";
import type { Context, Env, Hono } from "hono";

export function mountRemoteAuthorityRoutes<E extends Env>(
  app: Hono<E>,
  options: { snapshot: AuthorityPublicSnapshot; now: () => string },
) {
  const serve = (kind: "jwks" | "status") => (c: Context<E>) => {
    const value = options.snapshot.read(kind, options.now());
    if (!value)
      return c.json({ error: "remote authority unavailable" }, 503, {
        "Cache-Control": "no-store",
      });
    const headers = {
      "Cache-Control":
        kind === "jwks"
          ? `public, max-age=${REMOTE_AUTHORITY_JWKS_MAX_AGE_SECONDS}, must-revalidate`
          : "no-store",
      ETag: value.etag,
      Vary: "Accept-Encoding",
      "Content-Type": kind === "jwks" ? "application/json" : "application/jose",
    };
    if (c.req.header("If-None-Match") === value.etag) return c.body(null, 304, headers);
    return c.body(value.body, 200, headers);
  };
  app.get("/api/remote/jwks.json", serve("jwks"));
  app.get("/api/remote/authority-status.json", serve("status"));
}
