import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@flycockpit/ui/components/select";
import { useMutation } from "@tanstack/react-query";
import { useParams, useRouter } from "@tanstack/react-router";
import { Languages } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useHaptics } from "@/hooks/use-haptics";
import { isSupportedLocale, type Locale, SUPPORTED_LOCALES } from "@/i18n/config";
import { LOCALE_LABELS } from "@/i18n/labels";
import { useDeferredSession } from "@/stores/session";
import { orpc } from "@/utils/orpc";

/**
 * The real Base UI locale Select. Lazy-loaded by `language-switcher.tsx` on
 * first interaction so the shared Base UI overlay chunk stays off the eager
 * bundle. It mounts `defaultOpen` so the click that triggered the load opens
 * the list immediately — no effect, no second click.
 */
export default function LanguageSwitcherSelect() {
  const { i18n, t } = useTranslation();
  const { trigger } = useHaptics();
  const router = useRouter();
  // `strict: false` so the switcher renders under any matched route — the
  // top-level `/` redirect briefly mounts without `lang` in scope.
  const params = useParams({ strict: false });
  const { data: session } = useDeferredSession();

  // Silent server-side sync of the signed-in user's preference. The router's
  // global error toast handles failures — the URL switch already succeeded by
  // the time the mutation resolves, so a network error doesn't block the UI.
  const updateLocale = useMutation(orpc.auth.updateLocale.mutationOptions());

  const current: Locale = isSupportedLocale(i18n.language) ? i18n.language : "en-US";

  const handleChange = (value: Locale | null) => {
    if (!value || !isSupportedLocale(value)) return;
    trigger("selection");
    if (typeof window !== "undefined") {
      window.localStorage.setItem("locale", value);
    }
    // Swap the `lang` param in-place; preserve the current pathname suffix,
    // search, and hash. `to: "."` resolves to the active route, so the
    // updated `params` rebuild the URL with the new locale prefix.
    const currentLang = isSupportedLocale(params.lang) ? params.lang : null;
    if (currentLang) {
      void router.navigate({
        to: ".",
        params: (p) => ({ ...p, lang: value }),
        search: (s) => s,
        replace: true,
      });
    } else {
      // First load (the visitor is sitting on `/` mid-redirect) — point at
      // the new locale's home and let `$lang/` handle it.
      void router.navigate({ to: "/$lang", params: { lang: value }, replace: true });
    }
    // i18n.changeLanguage runs in `useChangeLanguage` once the URL updates,
    // but call it eagerly so the UI doesn't flash the old language.
    void i18n.changeLanguage(value);

    // Persist server-side so the choice follows the user across devices.
    // Skipped for unauthenticated visitors — there is nothing to persist to.
    if (session?.user && session.user.locale !== value) {
      updateLocale.mutate({ locale: value });
    }
  };

  return (
    <Select value={current} onValueChange={handleChange} defaultOpen>
      <SelectTrigger
        aria-label={t("languageLabel", { ns: "nav" })}
        size="touch"
        className="gap-2 px-3"
      >
        <Languages className="size-4" aria-hidden="true" />
        <SelectValue>{LOCALE_LABELS[current]}</SelectValue>
      </SelectTrigger>
      <SelectContent>
        {SUPPORTED_LOCALES.map((locale) => (
          <SelectItem key={locale} value={locale} className="min-h-[44px]">
            {LOCALE_LABELS[locale]}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
