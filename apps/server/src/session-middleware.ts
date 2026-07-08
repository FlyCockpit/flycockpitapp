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
export async function sessionMiddleware(c: Context, next: Next) {
  let session: Session | null = null;
  try {
    session = (await auth.api.getSession({ headers: c.req.raw.headers })) as Session | null;
  } catch (err) {
    console.warn("[session-middleware] getSession failed, treating as anonymous:", err);
    session = null;
  }
  c.set("session", session ?? null);
  await next();
}
