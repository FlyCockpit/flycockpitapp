import { isAdminRole } from "@flycockpit/auth/roles";
import type { LucideIcon } from "lucide-react";
import { Cookie, Home, Info, LayoutDashboard, Monitor, Settings, Shield } from "lucide-react";

export type NavDirection = "forward" | "back" | "none";
export type NavAudience = "public" | "authenticated" | "admin";
export type NavPlacement = "desktop" | "mobile" | "userMenu";
export type AppNavPath =
  | "/"
  | "/about"
  | "/cookie-policy"
  | "/dashboard"
  | "/instances"
  | "/settings"
  | "/admin"
  | "/settings/security"
  | "/settings/privacy";
export type LangNavRoute =
  | "/$lang"
  | "/$lang/about"
  | "/$lang/cookie-policy"
  | "/$lang/dashboard"
  | "/$lang/instances"
  | "/$lang/settings"
  | "/$lang/admin"
  | "/$lang/settings/security"
  | "/$lang/settings/privacy";

export type RouteNavItem = {
  /** Path WITHOUT the `/$lang/` prefix, starts with "/". Use "/" for root. */
  path: AppNavPath;
  /** Translation key. App nav keys live in `nav`; nested nav may use another namespace. */
  labelKey: string;
  /** Icon rendered by shell navigation surfaces. */
  icon: LucideIcon;
  /** `activeOptions.exact` for the <Link>. */
  exact: boolean;
};

export type AppNavItem = RouteNavItem & {
  id: "home" | "about" | "cookiePolicy" | "dashboard" | "instances" | "settings" | "admin";
  audience: NavAudience;
  placements: readonly NavPlacement[];
};

type VisibleNavInput = {
  placement: NavPlacement;
  isAuthenticated: boolean;
  role?: unknown;
};

export const appNavItems: AppNavItem[] = [
  {
    id: "home",
    path: "/",
    labelKey: "items.home",
    icon: Home,
    exact: true,
    audience: "public",
    placements: ["desktop", "mobile"],
  },
  {
    id: "about",
    path: "/about",
    labelKey: "items.about",
    icon: Info,
    exact: true,
    audience: "public",
    placements: ["desktop"],
  },
  {
    id: "cookiePolicy",
    path: "/cookie-policy",
    labelKey: "items.cookiePolicy",
    icon: Cookie,
    exact: true,
    audience: "public",
    placements: ["desktop"],
  },
  {
    id: "dashboard",
    path: "/dashboard",
    labelKey: "items.dashboard",
    icon: LayoutDashboard,
    exact: false,
    audience: "authenticated",
    placements: ["desktop", "mobile"],
  },
  {
    id: "instances",
    path: "/instances",
    labelKey: "items.instances",
    icon: Monitor,
    exact: false,
    audience: "authenticated",
    placements: ["desktop", "mobile"],
  },
  {
    id: "settings",
    path: "/settings",
    labelKey: "items.settings",
    icon: Settings,
    exact: false,
    audience: "authenticated",
    placements: ["desktop", "mobile", "userMenu"],
  },
  {
    id: "admin",
    path: "/admin",
    labelKey: "items.admin",
    icon: Shield,
    exact: false,
    audience: "admin",
    placements: ["desktop", "mobile", "userMenu"],
  },
];

function canSeeNavItem(item: AppNavItem, input: Pick<VisibleNavInput, "isAuthenticated" | "role">) {
  if (item.audience === "public") return true;
  if (!input.isAuthenticated) return false;
  if (item.audience === "authenticated") return true;
  return isAdminRole(input.role);
}

export function getNavItems(input: VisibleNavInput): AppNavItem[] {
  return appNavItems.filter(
    (item) => item.placements.includes(input.placement) && canSeeNavItem(item, input),
  );
}

export function toLangRoute(path: AppNavPath): LangNavRoute {
  if (path === "/") return "/$lang";
  return `/$lang${path}` as LangNavRoute;
}

/**
 * Settings sub-nav tabs, in left→right visual order. The array order is the
 * source of truth for `getNavDirection`'s sibling slide direction, so it MUST
 * match the order rendered in `settings.tsx`. Reuses the existing i18n keys.
 */
export const settingsNavItems: RouteNavItem[] = [
  {
    path: "/settings",
    labelKey: "settings:navProfile",
    icon: Settings,
    exact: true,
  },
  {
    path: "/settings/security",
    labelKey: "settings:navSecurity",
    icon: Shield,
    exact: false,
  },
  {
    path: "/settings/privacy",
    labelKey: "consent:settings.navPrivacy",
    icon: Cookie,
    exact: false,
  },
];

const NAV_LISTS: RouteNavItem[][] = [appNavItems, settingsNavItems];

export function stripLangPrefix(pathname: string): string {
  const match = pathname.match(/^\/[a-z]{2}(?:-[A-Z]{2})?(\/.*)?$/i);

  if (!match) {
    return pathname;
  }

  const rest = match[1] ?? "/";

  if (rest === "" || rest === "/") {
    return "/";
  }

  return rest;
}

export function getNavDirection(fromPath: string, toPath: string): NavDirection {
  if (fromPath === toPath) {
    return "none";
  }

  for (const list of NAV_LISTS) {
    const fromIndex = list.findIndex((item) => item.path === fromPath);
    const toIndex = list.findIndex((item) => item.path === toPath);

    if (fromIndex !== -1 && toIndex !== -1) {
      return toIndex < fromIndex ? "back" : "forward";
    }
  }

  if (fromPath !== "/" && toPath.startsWith(`${fromPath}/`)) {
    return "forward";
  }

  if (toPath !== "/" && fromPath.startsWith(`${toPath}/`)) {
    return "back";
  }

  return "forward";
}
