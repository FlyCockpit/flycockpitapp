import type { Context, Next } from "hono";

import { requireVerifiedAdminSession } from "./admin-session-gate";

// Better-Auth's api-key plugin exposes authenticated endpoints under
// `/api/auth/api-key/*`, but the plugin itself does not know this app treats
// API keys as an admin-only MCP credential. Gate those endpoints server-side
// so non-admin or unverified users cannot mint/manage keys even if they guess
// the route outside the 404-hidden admin UI.
export async function apiKeyAdminGate(c: Context, next: Next) {
  const result = await requireVerifiedAdminSession(c.req.raw.headers);
  if (!result.ok) {
    return c.json(
      { error: result.error, error_description: result.errorDescription },
      result.status,
    );
  }
  await next();
}
