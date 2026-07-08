import type { Context, Next } from "hono";

import { requireVerifiedAdminSession } from "./admin-session-gate";

// Better-Auth's admin plugin exposes a parallel management API under
// `/api/auth/admin/*`. Its built-in route checks validate the role, but they
// do not know this app also requires verified email and any globally forced
// second factor. Gate the whole plugin surface before `auth.handler`.
export async function betterAuthAdminGate(c: Context, next: Next) {
  const result = await requireVerifiedAdminSession(c.req.raw.headers);
  if (!result.ok) {
    return c.json(
      { error: result.error, error_description: result.errorDescription },
      result.status,
    );
  }
  await next();
}
