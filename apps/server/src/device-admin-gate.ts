import { isTwoFactorPolicySatisfied } from "@flycockpit/api/lib/two-factor-policy";
import { auth, type Session } from "@flycockpit/auth";
import prisma from "@flycockpit/db";
import type { Context, Next } from "hono";
import { requireVerifiedAdminSession } from "./admin-session-gate";

const COCKPIT_CLI_CLIENT_ID = "cockpit-cli";

type GateResult =
  | { ok: true; session: Session }
  | { ok: false; status: 401 | 403; error: string; errorDescription: string };

async function requireVerifiedUserSession(headers: Headers): Promise<GateResult> {
  let session: Session | null = null;
  try {
    session = (await auth.api.getSession({ headers })) as Session | null;
  } catch {
    session = null;
  }

  if (!session?.user) {
    return {
      ok: false,
      status: 401,
      error: "unauthorized",
      errorDescription: "Authentication required",
    };
  }

  if (!session.user.emailVerified) {
    return {
      ok: false,
      status: 403,
      error: "access_denied",
      errorDescription: "Verified account required",
    };
  }

  if (!(await isTwoFactorPolicySatisfied(session.user))) {
    return {
      ok: false,
      status: 403,
      error: "access_denied",
      errorDescription: "Two-factor authentication setup is required",
    };
  }

  return { ok: true, session };
}

async function readUserCode(c: Context): Promise<string | null> {
  try {
    const body = (await c.req.raw.clone().json()) as { userCode?: unknown; user_code?: unknown };
    if (typeof body.userCode === "string") return body.userCode;
    if (typeof body.user_code === "string") return body.user_code;
  } catch {
    return null;
  }
  return null;
}

async function isCockpitCliDeviceCode(userCode: string | null): Promise<boolean> {
  if (!userCode) return false;
  const row = await prisma.deviceCode.findUnique({
    where: { userCode },
    select: { clientId: true },
  });
  return row?.clientId === COCKPIT_CLI_CLIENT_ID;
}

// Gate for the better-auth deviceAuthorization plugin's approve/deny endpoints.
// cockpit-cli device codes are user-owned: any verified, policy-satisfied user
// may approve their own CLI login. Existing admin/MCP device flows stay behind
// the verified-admin gate by falling back for every other client id.
export async function deviceAdminGate(c: Context, next: Next) {
  const userCode = await readUserCode(c);
  const result = (await isCockpitCliDeviceCode(userCode))
    ? await requireVerifiedUserSession(c.req.raw.headers)
    : await requireVerifiedAdminSession(c.req.raw.headers);

  if (!result.ok) {
    return c.json(
      { error: result.error, error_description: result.errorDescription },
      result.status,
    );
  }
  await next();
}
