import { auth, type Session } from "@flycockpit/auth";
import type { Context as HonoContext } from "hono";

export type CreateContextOptions = {
  context: HonoContext;
};

export async function createContext({ context }: CreateContextOptions) {
  // The session is resolved once per request by `sessionMiddleware` in
  // apps/server. Test harnesses that bypass the Hono middleware stack will
  // see undefined here — fall back to a direct lookup so they still work.
  const preresolved = context.get("session") as Session | null | undefined;
  if (preresolved !== undefined) {
    return { session: preresolved };
  }

  // Fallback path. Strip `Authorization` for the same reason sessionMiddleware
  // does: oRPC is a cookie-authenticated surface; Bearer API keys belong to MCP
  // where their read/write scope is enforced.
  const cookieOnly = new Headers(context.req.raw.headers);
  cookieOnly.delete("authorization");
  const session = (await auth.api.getSession({ headers: cookieOnly })) as Session | null;
  return {
    session,
  };
}

export type Context = Awaited<ReturnType<typeof createContext>>;
