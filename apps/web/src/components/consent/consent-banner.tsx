import { Button } from "@flycockpit/ui/components/button";
import { Link, useParams } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

import { useConsent } from "@/hooks/use-consent";
import { useHaptics } from "@/hooks/use-haptics";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { recordConsentToServer } from "@/lib/consent-server";

/**
 * First-visit consent banner. Non-modal (it does not trap focus or block the
 * page — the *gating engine*, not this UI, is what stops non-essential
 * scripts) but the three choices have equal prominence: "Reject all" is as
 * easy and visible as "Accept all", per GDPR / no-dark-pattern guidance.
 *
 * Copy is i18n chrome (must render in every locale, even offline); the
 * long-form cookie policy lives in the CMS at `/$lang/cookie-policy`.
 */
export function ConsentBanner({ onCustomize }: { onCustomize: () => void }) {
  const { t } = useTranslation("consent");
  const { acceptAll, rejectAll } = useConsent();
  const { trigger } = useHaptics();
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;

  const decide = (kind: "accept_all" | "reject_all") => {
    if (kind === "accept_all") acceptAll();
    else rejectAll();
    recordConsentToServer(kind);
    trigger("success");
  };

  return (
    <div
      role="region"
      aria-label={t("banner.title")}
      className="fixed inset-x-0 bottom-0 z-[60] border-t bg-background/95 backdrop-blur-lg md:inset-x-auto md:right-4 md:bottom-4 md:max-w-md md:rounded-xl md:border md:ring-1 md:ring-foreground/10"
      style={{
        paddingBottom: "calc(var(--safe-area-bottom) + 3.5rem)",
        paddingLeft: "var(--safe-area-left)",
        paddingRight: "var(--safe-area-right)",
      }}
    >
      <div className="mx-auto flex max-w-3xl flex-col gap-3 p-4 md:p-5">
        <div className="space-y-1">
          <p className="text-sm font-medium text-foreground">{t("banner.title")}</p>
          <p className="text-xs/relaxed text-muted-foreground">{t("banner.message")}</p>
          <Link
            to="/$lang/cookie-policy"
            params={{ lang }}
            className="inline-block text-xs text-primary underline underline-offset-3 hover:text-foreground"
          >
            {t("banner.policyLink")}
          </Link>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
          <Button
            variant="ghost"
            className="min-h-[44px] sm:mr-auto"
            onClick={() => {
              trigger("selection");
              onCustomize();
            }}
          >
            {t("banner.customize")}
          </Button>
          <Button variant="outline" className="min-h-[44px]" onClick={() => decide("reject_all")}>
            {t("banner.rejectAll")}
          </Button>
          <Button className="min-h-[44px]" onClick={() => decide("accept_all")}>
            {t("banner.acceptAll")}
          </Button>
        </div>
      </div>
    </div>
  );
}
