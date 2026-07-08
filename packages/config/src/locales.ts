/**
 * Shared locale constants. Imported by both the web app's i18n config and the
 * API package's auth routers so the two stay in lockstep. Adding a locale
 * is a single edit here.
 *
 * Adding a locale:
 *   1. Append the BCP 47 tag to `SUPPORTED_LOCALES`.
 *   2. Drop matching translation JSON files into `apps/web/src/locales/<tag>/`.
 *
 * No DB migration is required — `User.locale` are
 * free-form String columns, validated at the API boundary by this list.
 */
export const SUPPORTED_LOCALES = ["en-US", "es-MX"] as const;

export type Locale = (typeof SUPPORTED_LOCALES)[number];

export const DEFAULT_LOCALE: Locale = "en-US";

export function isSupportedLocale(value: unknown): value is Locale {
  return typeof value === "string" && (SUPPORTED_LOCALES as readonly string[]).includes(value);
}
