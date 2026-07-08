import { Button } from "@flycockpit/ui/components/button";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { lazy, Suspense, useState } from "react";
import { useTranslation } from "react-i18next";

import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { useDeferredSession } from "@/stores/session";
import { orpc } from "@/utils/orpc";

// Lazy so the shared Base UI overlay chunk (Menu/Dialog/focus-guards) leaves the
// eager first-paint bundle. Only the signed-in branch touches Base UI; the
// pending Skeleton and signed-out Buttons/Links stay fully eager. The shell
// below reproduces the trigger Button exactly, so the swap is zero-CLS.
const UserMenuContent = lazy(() => import("./user-menu-content"));

// Warm the chunk on hover/focus. The module cache dedupes repeat calls, so the
// click handler that follows resolves instantly from cache.
function prefetchMenu() {
  void import("./user-menu-content");
}

export default function UserMenu() {
  // `strict: false` so the menu renders under both prefixed and (briefly) the
  // top-level `/` redirect route without throwing.
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  const { data: session, isPending } = useDeferredSession();
  const config = useQuery(orpc.appConfig.queryOptions());
  const { t } = useTranslation("nav");
  const [mounted, setMounted] = useState(false);

  if (isPending) {
    return <Skeleton className="h-11 w-24" />;
  }

  if (!session) {
    // Default to NOT showing Sign Up until the flag is known, so it never
    // flashes when signup is disabled.
    const showSignUp = !config.isPending && config.data?.signupEnabled === true;
    return (
      <div className="flex items-center gap-2">
        {showSignUp && (
          <Link to="/$lang/signup" params={{ lang }} search={{ redirectTo: undefined }}>
            <Button size="touch">{t("userMenu.signUp")}</Button>
          </Link>
        )}
        <Link to="/$lang/login" params={{ lang }} search={{ redirectTo: undefined }}>
          <Button size="touch" variant="outline">
            {t("userMenu.signIn")}
          </Button>
        </Link>
      </div>
    );
  }

  // The eager placeholder: visually identical to UserMenuContent's trigger so
  // there is no layout shift when the real control loads. `inert` while the
  // lazy chunk is in flight (Suspense fallback) so it can't take a second,
  // ignored click.
  const shell = (inert: boolean) => (
    <Button
      variant="outline"
      size="touch"
      aria-haspopup="menu"
      inert={inert}
      onPointerEnter={prefetchMenu}
      onFocus={prefetchMenu}
      onClick={() => {
        prefetchMenu();
        setMounted(true);
      }}
    >
      {session.user.name}
    </Button>
  );

  if (!mounted) return shell(false);

  return (
    <Suspense fallback={shell(true)}>
      <UserMenuContent />
    </Suspense>
  );
}
