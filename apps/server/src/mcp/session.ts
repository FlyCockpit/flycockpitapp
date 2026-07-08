import { createHash } from "node:crypto";
import { type Session as AuthSession, auth } from "@flycockpit/auth";
import { isAdminRole } from "@flycockpit/auth/roles";
import prisma from "@flycockpit/db";

type McpApiKeyScope = "read" | "write";
export type Session = AuthSession & {
  mcpApiKeyScope?: McpApiKeyScope;
};

// Resolves a Better-Auth session for an inbound `/mcp` request from the
// `Authorization: Bearer <token>` header *only*. The api-key plugin
// (configured with `enableSessionForAPIKeys: true`) mocks a session when it
// sees a valid bearer token; the device-authorization grant issues real
// session tokens. Both paths funnel through `auth.api.getSession`, but we
// forward only the Authorization header so cookies and any other credential
// source on the inbound request cannot authenticate `/mcp` — that surface
// belongs to the admin UI under `/rpc/*`. Browsers do not auto-attach
// Authorization cross-origin, which is the property the "no CSRF needed"
// note in the MCP auth contract depends on; allowing cookie auth here would
// silently invalidate it.
//
// Returns `null` for any failure mode (missing/non-bearer Authorization
// header, invalid token, valid non-admin user, unverified admin). Callers should respond 401
// without a body — leaking the difference between "no token" and "valid
// token but not a verified admin" turns this endpoint into an admin-role oracle.
export async function getAdminSessionFromHeaders(headers: Headers): Promise<Session | null> {
  const authorization = headers.get("authorization");
  if (!authorization) {
    return null;
  }
  const match = /^bearer\s+(\S.*)$/i.exec(authorization.trim());
  const token = match?.[1];
  if (!token) {
    return null;
  }

  const bearerOnly = new Headers();
  bearerOnly.set("authorization", authorization);

  let session: Session | null = null;
  try {
    session = (await auth.api.getSession({ headers: bearerOnly })) as Session | null;
  } catch {
    return null;
  }
  if (!session?.user?.emailVerified || !isAdminRole(session.user.role)) {
    return null;
  }
  const keyHash = createHash("sha256").update(token).digest("base64url");
  const apiKey = await prisma.apiKey.findFirst({
    where: { key: keyHash },
    select: { permissions: true },
  });
  if (apiKey) {
    const scope = parseMcpScope(apiKey.permissions);
    if (!scope) return null;
    return { ...session, mcpApiKeyScope: scope };
  }
  return session;
}

function parseMcpScope(raw: string | null): McpApiKeyScope | null {
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as unknown;
    const mcp = value && typeof value === "object" ? (value as { mcp?: unknown }).mcp : null;
    if (!Array.isArray(mcp)) return null;
    if (mcp.includes("write")) return "write";
    if (mcp.includes("read")) return "read";
    return null;
  } catch {
    return null;
  }
}
