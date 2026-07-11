import { createServerFn } from "@tanstack/react-start";
import { getRequestHeaders } from "@tanstack/react-start/server";

import {
  failedRouteSessionResolution,
  type RouteSession,
  type RouteSessionResolution,
  resolvedRouteSession,
} from "@/lib/route-session-access";

type BetterAuthRouteSession = {
  user: {
    id: string;
    name: string;
    email: string;
    emailVerified: boolean;
    role?: string | null;
    twoFactorEnabled?: boolean | null;
  };
};

type GetBetterAuthSession = (context: {
  headers: Headers;
}) => Promise<BetterAuthRouteSession | null>;

export const getRouteSession = createServerFn({ method: "GET" }).handler(
  async (): Promise<RouteSessionResolution> => {
    const { auth } = await import("@flycockpit/auth");
    return resolveRouteSessionFromAuth(getRequestHeaders(), auth.api.getSession);
  },
);

export async function resolveRouteSessionFromAuth(
  headers: Headers,
  getSession: GetBetterAuthSession,
): Promise<RouteSessionResolution> {
  try {
    const session = await getSession({ headers });
    return resolvedRouteSession(toRouteSession(session));
  } catch {
    return failedRouteSessionResolution();
  }
}

export function toRouteSession(session: BetterAuthRouteSession | null): RouteSession | null {
  if (!session) return null;

  return {
    user: {
      id: session.user.id,
      name: session.user.name,
      email: session.user.email,
      emailVerified: session.user.emailVerified,
      role: session.user.role,
      twoFactorEnabled: session.user.twoFactorEnabled,
    },
  };
}
