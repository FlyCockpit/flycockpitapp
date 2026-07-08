import { cn } from "@flycockpit/ui/lib/utils";
import { useTranslation } from "react-i18next";

import { useConsentUi } from "@/stores/consent-ui";

/**
 * Persistent "Cookie preferences" trigger. GDPR requires withdrawal to be as
 * easy as granting, so drop this into your site footer / CMS pages and the
 * settings area. It re-opens the preferences modal from anywhere (state lives
 * in the consent-ui store, not local component state).
 */
export function CookiePreferencesLink({ className }: { className?: string }) {
  const { t } = useTranslation("consent");
  const openPreferences = useConsentUi((s) => s.openPreferences);

  return (
    <button
      type="button"
      onClick={openPreferences}
      className={cn(
        "inline-flex min-h-[44px] items-center text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground",
        className,
      )}
    >
      {t("preferences.open")}
    </button>
  );
}
