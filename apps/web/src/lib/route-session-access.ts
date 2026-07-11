import { isAdminRole } from "@flycockpit/auth/roles";

type RouteSessionUser = {
  id: string;
  name: string;
  email: string;
  emailVerified: boolean;
  role?: string | null;
  twoFactorEnabled?: boolean | null;
};

export type RouteSession = {
  user: RouteSessionUser;
};

export type RouteSessionResolution =
  | { status: "resolved"; session: RouteSession | null }
  | { status: "error" };

export type ProtectedRouteDecision =
  | { kind: "allow"; session: RouteSession }
  | { kind: "redirect-to-login" }
  | { kind: "error" };

export type AnonymousOnlyRouteDecision =
  | { kind: "allow" }
  | { kind: "redirect-authenticated"; session: RouteSession }
  | { kind: "error" };

export type AdminRouteDecision =
  | { kind: "allow"; session: RouteSession }
  | { kind: "not-found" }
  | { kind: "error" };

export type DeviceRouteDecision =
  | { kind: "allow"; session: RouteSession }
  | { kind: "redirect-to-login" }
  | { kind: "redirect-to-dashboard" }
  | { kind: "error" };

export function resolvedRouteSession(session: RouteSession | null): RouteSessionResolution {
  return { status: "resolved", session };
}

export function failedRouteSessionResolution(): RouteSessionResolution {
  return { status: "error" };
}

export function decideProtectedRouteAccess(
  resolution: RouteSessionResolution,
): ProtectedRouteDecision {
  if (resolution.status === "error") return { kind: "error" };
  if (!resolution.session) return { kind: "redirect-to-login" };
  return { kind: "allow", session: resolution.session };
}

export function decideAnonymousOnlyRouteAccess(
  resolution: RouteSessionResolution,
): AnonymousOnlyRouteDecision {
  if (resolution.status === "error") return { kind: "error" };
  if (!resolution.session) return { kind: "allow" };
  return { kind: "redirect-authenticated", session: resolution.session };
}

export function decideAdminRouteAccess(resolution: RouteSessionResolution): AdminRouteDecision {
  if (resolution.status === "error") return { kind: "error" };
  const user = resolution.session?.user;
  if (!resolution.session || !user?.emailVerified || !isAdminRole(user.role)) {
    return { kind: "not-found" };
  }
  return { kind: "allow", session: resolution.session };
}

export function decideDeviceRouteAccess(resolution: RouteSessionResolution): DeviceRouteDecision {
  if (resolution.status === "error") return { kind: "error" };
  const user = resolution.session?.user;
  if (!resolution.session) return { kind: "redirect-to-login" };
  if (!user?.emailVerified) return { kind: "redirect-to-dashboard" };
  return { kind: "allow", session: resolution.session };
}
