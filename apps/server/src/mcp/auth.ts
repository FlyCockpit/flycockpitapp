// AsyncLocalStorage that carries the resolved admin user through MCP tool
// handlers. The transport layer wraps `handleRequest` in `mcpContextStorage.run`
// so every oRPC procedure invoked from a tool sees the same authenticated
// user as a normal /rpc request would.
import { AsyncLocalStorage } from "node:async_hooks";
import type { Context, Next } from "hono";

import { getAdminSessionFromHeaders, type Session } from "./session";

interface McpContext {
  session: Session;
}

// Exported so the colocated test files can drive the middleware/tools through
// a real AsyncLocalStorage instance instead of stubbing it. Production code
// outside this module should reach for `getMcpContext()` instead.
export const mcpContextStorage = new AsyncLocalStorage<McpContext>();

export function getMcpContext(): McpContext {
  const ctx = mcpContextStorage.getStore();
  if (!ctx) {
    throw new Error("MCP context not available — did the request bypass mcpAuthMiddleware?");
  }
  return ctx;
}

// Hono middleware that gates the `/mcp` endpoint. Resolves a Better-Auth
// session from the `Authorization: Bearer <token>` header — works for both
// scoped admin API keys (the api-key plugin mocks a session) and OAuth access
// tokens issued by the device-authorization grant. Non-admin or invalid
// tokens get a body-less 401: we deliberately do not distinguish "invalid
// token" from "valid token but not admin" so the endpoint cannot be used as
// an admin-role oracle.
export async function mcpAuthMiddleware(c: Context, next: Next) {
  const session = await getAdminSessionFromHeaders(c.req.raw.headers);
  if (!session) {
    return c.body(null, 401);
  }
  c.set("admin", session.user);
  return mcpContextStorage.run({ session }, () => next());
}
