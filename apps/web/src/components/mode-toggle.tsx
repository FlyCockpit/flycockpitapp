import { Button } from "@flycockpit/ui/components/button";
import { Moon, Sun } from "lucide-react";
import { lazy, Suspense, useState } from "react";
import { useTranslation } from "react-i18next";

// Lazy so the shared Base UI overlay chunk (Menu/Dialog/focus-guards) leaves
// the eager first-paint bundle. The shell below is a plain <Button> identical
// to the real trigger, so the swap is zero-CLS. See lazy-qr-code.tsx for the
// component-level dynamic-import precedent.
const ModeToggleMenu = lazy(() => import("./mode-toggle-menu"));

// Warm the chunk on hover/focus. The module cache dedupes repeat calls, so the
// click handler that follows resolves instantly from cache.
function prefetchMenu() {
  void import("./mode-toggle-menu");
}

export function ModeToggle() {
  const { t } = useTranslation("nav");
  const [mounted, setMounted] = useState(false);

  // The eager placeholder: visually identical to ModeToggleMenu's trigger so
  // there is no layout shift when the real control loads. `inert` while the
  // lazy chunk is in flight (Suspense fallback) so it can't receive a second,
  // ignored click.
  const shell = (inert: boolean) => (
    <Button
      variant="outline"
      size="icon-touch"
      aria-haspopup="menu"
      inert={inert}
      onPointerEnter={prefetchMenu}
      onFocus={prefetchMenu}
      onClick={() => {
        prefetchMenu();
        setMounted(true);
      }}
    >
      <Sun className="size-[1.2rem] scale-100 rotate-0 transition-transform dark:scale-0 dark:-rotate-90" />
      <Moon className="absolute size-[1.2rem] scale-0 rotate-90 transition-transform dark:scale-100 dark:rotate-0" />
      <span className="sr-only">{t("themeToggle.label")}</span>
    </Button>
  );

  if (!mounted) return shell(false);

  return (
    <Suspense fallback={shell(true)}>
      <ModeToggleMenu />
    </Suspense>
  );
}
