import { Button } from "@flycockpit/ui/components/button";
import { ResponsiveDialog } from "@flycockpit/ui/components/responsive-dialog";
import { Switch } from "@flycockpit/ui/components/switch";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useConsent } from "@/hooks/use-consent";
import { useHaptics } from "@/hooks/use-haptics";
import { type ConsentState, OPTIONAL_CATEGORIES, type OptionalCategory } from "@/lib/consent";
import { recordConsentToServer } from "@/lib/consent-server";

/**
 * Granular per-category preferences. "Strictly necessary" is shown but locked
 * on. Save / Accept all / Reject all all have equal prominence and are 44px
 * touch targets (PWA rule). The form state is seeded once per open via a
 * `key` remount — never `useEffect` (repo rule).
 */
export function ConsentPreferences({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { t } = useTranslation("consent");
  return (
    <ResponsiveDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t("preferences.title")}
      description={t("preferences.description")}
      className="md:max-w-md"
    >
      {/* Remount on each open so the toggles re-seed from the live decision. */}
      <PreferencesForm key={String(open)} onDone={() => onOpenChange(false)} />
    </ResponsiveDialog>
  );
}

function PreferencesForm({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation("consent");
  const { consent, setConsent } = useConsent();
  const { trigger } = useHaptics();
  const [draft, setDraft] = useState<ConsentState>({ ...consent });

  const commit = (next: ConsentState, action: "accept_all" | "reject_all" | "custom") => {
    setConsent(next);
    recordConsentToServer(action);
    trigger("success");
    onDone();
  };

  return (
    <div className="space-y-4 py-2">
      <CategoryRow
        name={t("categories.necessary.name")}
        description={t("categories.necessary.description")}
        control={
          <span className="text-xs font-medium text-muted-foreground">
            {t("categories.alwaysOn")}
          </span>
        }
      />
      {OPTIONAL_CATEGORIES.map((category: OptionalCategory) => (
        <CategoryRow
          key={category}
          name={t(`categories.${category}.name`)}
          description={t(`categories.${category}.description`)}
          control={
            <Switch
              checked={draft[category]}
              onCheckedChange={(checked) => {
                trigger("selection");
                setDraft((d) => ({ ...d, [category]: checked }));
              }}
              aria-label={t(`categories.${category}.name`)}
            />
          }
        />
      ))}

      <div className="flex flex-col gap-2 pt-2 sm:flex-row sm:justify-end">
        <Button
          variant="outline"
          className="min-h-[44px] sm:mr-auto"
          onClick={() =>
            commit({ functional: false, analytics: false, marketing: false }, "reject_all")
          }
        >
          {t("preferences.rejectAll")}
        </Button>
        <Button
          variant="secondary"
          className="min-h-[44px]"
          onClick={() => commit(draft, "custom")}
        >
          {t("preferences.save")}
        </Button>
        <Button
          className="min-h-[44px]"
          onClick={() =>
            commit({ functional: true, analytics: true, marketing: true }, "accept_all")
          }
        >
          {t("preferences.acceptAll")}
        </Button>
      </div>
    </div>
  );
}

function CategoryRow({
  name,
  description,
  control,
}: {
  name: string;
  description: string;
  control: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="space-y-0.5">
        <p className="text-sm font-medium text-foreground">{name}</p>
        <p className="text-xs/relaxed text-muted-foreground">{description}</p>
      </div>
      <div className="flex min-h-[44px] shrink-0 items-center">{control}</div>
    </div>
  );
}
