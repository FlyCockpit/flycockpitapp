import { useEffect } from "react";

import i18n from "@/i18n";
import { isSupportedLocale } from "@/i18n/config";

/**
 * Sync i18next's active language with the URL's `:lang` param.
 *
 * Lives in `apps/web/src/hooks/` — the approved escape hatch for `useEffect`
 * (CLAUDE.md → React useEffect Policy). Component files cannot call
 * `useEffect` directly, so the language switch happens here behind a named
 * hook.
 *
 * Persists to `localStorage` so a subsequent visit without a URL prefix still
 * lands on the user's last-chosen locale (the i18next LanguageDetector reads
 * the same `locale` key).
 */
export function useChangeLanguage(lang: string) {
  useEffect(() => {
    if (!isSupportedLocale(lang)) return;
    if (i18n.language !== lang) {
      void i18n.changeLanguage(lang);
    }
    if (typeof window !== "undefined") {
      window.localStorage.setItem("locale", lang);
    }
  }, [lang]);
}
