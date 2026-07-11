import { auth, type Session } from "@flycockpit/auth";
import type { Context, Next } from "hono";

// Resolves the Better-Auth session once per request and stashes it on the
// Hono context. Downstream consumers (rate limiter, oRPC createContext, the
// /sw/push-renew handler) read `c.get("session")` instead of each making
// their own database hit.
//
// Failure mode: a Better-Auth blip becomes "no session" rather than a 500
// for the entire request. The downstream `requireAuth` gates will still
// return 401 if a real session was needed.
//
// SECURITY: `Authorization` is stripped before resolving, so routes guarded by
// this middleware authenticate by cookie only. API keys are MCP credentials;
// forwarding a Bearer key here would let Better Auth's api-key plugin mock a
// full admin session for /rpc procedures that do not enforce MCP read/write
// scope.
export async function sessionMiddleware(c: Context, next: Next) {
  let session: Session | null = null;
  try {
    const cookieOnly = new Headers(c.req.raw.headers);
    cookieOnly.delete("authorization");
    session = (await auth.api.getSession({ headers: cookieOnly })) as Session | null;
  } catch (err) {
    console.warn("[session-middleware] getSession failed, treating as anonymous:", err);
    session = null;
  }
  c.set("session", session ?? null);
  await next();
}
