import { useParams, useRouter } from "@tanstack/react-router";
import { useEffect } from "react";

import i18n from "@/i18n";
import { isSupportedLocale } from "@/i18n/config";
import { useDeferredSession } from "@/stores/session";

/**
 * Sync a signed-in user's stored locale (Prisma `User.locale`) into the
 * i18n detection chain. Order: URL `:lang` (always wins) → localStorage →
 * **user.locale** → navigator → DEFAULT_LOCALE.
 *
 * Why a hook instead of an i18next-browser-languagedetector entry: the
 * session resolves asynchronously (after the initial i18n init), so the
 * detector chain has already settled by the time we know who the user is.
 * The cleanest path is to detect the session resolution in React and
 * navigate to the user's preferred locale URL once — which then drives
 * the existing `urlPath` detector + `useChangeLanguage` flow.
 *
 * We deliberately skip the redirect when:
 *   - the user is unauthenticated (no preference to honor),
 *   - the user has explicitly set a different locale this session
 *     (`localStorage.locale` exists — that beats the server-side preference,
 *     mirroring the i18next detector order),
 *   - the URL already matches the user's preferred locale (no-op),
 *   - the stored locale is not in `SUPPORTED_LOCALES` (server may carry an
 *     older value that was retired client-side).
 *
 * Lives in `apps/web/src/hooks/` — the approved escape hatch for
 * `useEffect` per CLAUDE.md "React useEffect Policy."
 */
export function useUserLocaleSync(): void {
  const { data: session } = useDeferredSession();
  const router = useRouter();
  // `strict: false` so we render under the brief `/` redirect window where
  // `lang` isn't matched yet.
  const params = useParams({ strict: false });

  const userLocale = session?.user?.locale;

  useEffect(() => {
    if (!userLocale) return;
    if (!isSupportedLocale(userLocale)) return;
    if (typeof window === "undefined") return;
    // localStorage is the explicit "I picked this on this device" signal —
    // honor it over the server-side preference.
    if (window.localStorage.getItem("locale")) return;
    // No-op when the URL is already in the right locale (the common case
    // after the very first render).
    const currentLang = isSupportedLocale(params.lang) ? params.lang : null;
    if (currentLang === userLocale) return;
    // Fall through to the URL-driven `useChangeLanguage` hook in
    // `routes/$lang.tsx`. We only navigate when the URL actually carries a
    // `lang` param; the brief `/` redirect window handles itself.
    if (currentLang) {
      void router.navigate({
        to: ".",
        params: (p) => ({ ...p, lang: userLocale }),
        search: (s) => s,
        replace: true,
      });
    } else {
      // Fallback: i18next is the source of truth until the URL settles.
      void i18n.changeLanguage(userLocale);
    }
  }, [userLocale, params.lang, router]);
}
