import { Link, useParams } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { useAuthSessionSnapshot } from "@/hooks/use-auth-session";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { getNavItems, toLangRoute } from "@/lib/nav-items";

export default function BottomNav({ hidden }: { hidden?: boolean }) {
  // `strict: false` keeps this safe to render under any matched route (the
  // top-level `/` redirect leaves no `lang` param). Fall back to the default
  // locale rather than crashing.
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  const { data: session, isPending } = useAuthSessionSnapshot();
  const { t } = useTranslation("nav");
  const items = getNavItems({
    placement: "mobile",
    isAuthenticated: !isPending && Boolean(session),
    role: session?.user.role,
  });

  if (hidden) return null;

  return (
    <nav
      className="fixed bottom-0 left-0 right-0 z-50 border-t bg-background/80 backdrop-blur-lg md:hidden"
      style={{ paddingBottom: "var(--safe-area-bottom)" }}
    >
      <div className="flex items-center justify-around h-14">
        {items.map((item) => (
          <Link
            key={item.id}
            to={toLangRoute(item.path)}
            params={{ lang }}
            activeOptions={{ exact: item.exact }}
            className="flex flex-col items-center justify-center gap-0.5 px-3 py-1.5 text-muted-foreground transition-colors min-w-[64px] min-h-[44px]"
            activeProps={{
              className:
                "flex flex-col items-center justify-center gap-0.5 px-3 py-1.5 text-primary transition-colors min-w-[64px] min-h-[44px]",
            }}
          >
            <item.icon className="size-5" />
            <span className="text-[10px] font-medium leading-tight">{t(item.labelKey)}</span>
          </Link>
        ))}
      </div>
    </nav>
  );
}
