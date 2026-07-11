import type { Locale } from "./config";

/**
 * Human-readable display labels for each supported locale. Lives next to the
 * other i18n config so the language switcher, the "translated by" banner, and
 * any future admin UI all pull from one place.
 *
 * Note: these strings stay in their native language by design — the dropdown
 * should always read "Español (México)" so a Spanish speaker recognises their
 * own language. They are NOT routed through i18n.
 */
export const LOCALE_LABELS: Record<Locale, string> = {
  "en-US": "English (US)",
  "es-MX": "Español (México)",
};
