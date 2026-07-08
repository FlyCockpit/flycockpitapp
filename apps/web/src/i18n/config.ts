// Locale constants live in `@flycockpit/config/locales` so the API package can
// import the same source of truth (it's the only thing that prevents
// SUPPORTED_LOCALES drifting between the auth router, the CMS translate jobs,
// and this file). Re-exported here so existing call sites keep working.
export {
  DEFAULT_LOCALE,
  isSupportedLocale,
  type Locale,
  SUPPORTED_LOCALES,
} from "@flycockpit/config/locales";

export const NAMESPACES = [
  "common",
  "auth",
  "errors",
  "validation",
  "admin",
  "dashboard",
  "instances",
  "settings",
  "nav",
  "marketing",
  "videos",
  "consent",
] as const;
