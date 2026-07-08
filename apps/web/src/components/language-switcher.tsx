import { cn } from "@flycockpit/ui/lib/utils";
import { ChevronDownIcon, Languages } from "lucide-react";
import { lazy, Suspense, useState } from "react";
import { useTranslation } from "react-i18next";

import { isSupportedLocale, type Locale } from "@/i18n/config";
import { LOCALE_LABELS } from "@/i18n/labels";

// Lazy so the shared Base UI overlay chunk (Select/focus-guards/floating-ui)
// leaves the eager first-paint bundle. The shell below reproduces SelectTrigger's
// rendered DOM exactly, so the swap to the real control is zero-CLS.
const LanguageSwitcherSelect = lazy(() => import("./language-switcher-select"));

// Warm the chunk on hover/focus. The module cache dedupes repeat calls, so the
// click handler that follows resolves instantly from cache.
function prefetchSelect() {
  void import("./language-switcher-select");
}

// Mirrors the className that `SelectTrigger` (size="touch") applies, plus the
// caller's `gap-2 px-3`. Kept in sync with packages/ui/src/components/select.tsx.
const TRIGGER_CLASS =
  "flex w-fit items-center justify-between gap-1.5 rounded-none border border-input bg-transparent py-2 pr-2 pl-2.5 text-xs whitespace-nowrap transition-colors outline-none select-none focus-visible:border-ring focus-visible:ring-1 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-1 aria-invalid:ring-destructive/20 data-placeholder:text-muted-foreground data-[size=default]:h-8 data-[size=sm]:h-7 data-[size=sm]:rounded-none data-[size=touch]:h-11 *:data-[slot=select-value]:line-clamp-1 *:data-[slot=select-value]:flex *:data-[slot=select-value]:items-center *:data-[slot=select-value]:gap-1.5 dark:bg-input/30 dark:hover:bg-input/50 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4 gap-2 px-3";

export function LanguageSwitcher() {
  const { i18n, t } = useTranslation();
  const [mounted, setMounted] = useState(false);

  const current: Locale = isSupportedLocale(i18n.language) ? i18n.language : "en-US";

  // The eager placeholder: a plain button reproducing SelectTrigger's DOM
  // (data-slot, data-size, ChevronDownIcon, the SelectValue span) so swapping
  // to the real Select causes no layout shift. `inert` while the lazy chunk is
  // in flight so it can't take a second, ignored click.
  const shell = (inert: boolean) => (
    <button
      type="button"
      data-slot="select-trigger"
      data-size="touch"
      aria-label={t("languageLabel", { ns: "nav" })}
      aria-haspopup="listbox"
      className={cn(TRIGGER_CLASS)}
      inert={inert}
      onPointerEnter={prefetchSelect}
      onFocus={prefetchSelect}
      onClick={() => {
        prefetchSelect();
        setMounted(true);
      }}
    >
      <Languages className="size-4" aria-hidden="true" />
      <span data-slot="select-value" className="flex flex-1 text-left">
        {LOCALE_LABELS[current]}
      </span>
      <ChevronDownIcon className="pointer-events-none size-4 text-muted-foreground" />
    </button>
  );

  if (!mounted) return shell(false);

  return (
    <Suspense fallback={shell(true)}>
      <LanguageSwitcherSelect />
    </Suspense>
  );
}
