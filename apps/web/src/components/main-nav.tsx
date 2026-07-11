import { cn } from "@flycockpit/ui/lib/utils";
import { Link, useParams } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { useAuthSessionSnapshot } from "@/hooks/use-auth-session";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { getNavItems, toLangRoute } from "@/lib/nav-items";

export function MainNav() {
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  const { data: session, isPending } = useAuthSessionSnapshot();
  const { t } = useTranslation("nav");
  const items = getNavItems({
    placement: "desktop",
    isAuthenticated: !isPending && Boolean(session),
    role: session?.user.role,
  });

  return (
    <nav
      aria-label={t("mainNav.ariaLabel")}
      className="hidden min-w-0 flex-1 overflow-x-auto no-scrollbar md:block"
    >
      <div className="flex w-max items-center gap-1">
        {items.map((item) => (
          <Link
            key={item.id}
            to={toLangRoute(item.path)}
            params={{ lang }}
            activeOptions={{ exact: item.exact }}
            className={cn(
              "inline-flex min-h-9 shrink-0 items-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
            )}
            activeProps={{
              className: "bg-muted text-foreground",
            }}
          >
            <item.icon aria-hidden="true" className="size-4" />
            <span>{t(item.labelKey)}</span>
          </Link>
        ))}
      </div>
    </nav>
  );
}
