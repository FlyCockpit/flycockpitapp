import { env } from "@flycockpit/env/web";
import { Link, useParams } from "@tanstack/react-router";

import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { LanguageSwitcher } from "./language-switcher";
import { MainNav } from "./main-nav";
import { ModeToggle } from "./mode-toggle";
import { NotificationInbox } from "./notifications/notification-inbox";
import UserMenu from "./user-menu";

export default function Header() {
  const appName = env.VITE_APP_NAME;
  // `strict: false` lets this component render under any route (including the
  // top-level `/` redirect) without throwing when the `lang` param is absent.
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;

  return (
    <div style={{ viewTransitionName: "site-header" }}>
      <div className="flex min-w-0 flex-row items-center gap-4 px-4 py-2">
        <Link
          to="/$lang"
          params={{ lang }}
          className="min-w-0 max-w-40 shrink-0 truncate font-semibold text-lg sm:max-w-56 lg:max-w-none"
        >
          {appName}
        </Link>
        <MainNav />
        <div className="ml-auto flex shrink-0 items-center gap-2">
          <NotificationInbox />
          <LanguageSwitcher />
          <ModeToggle />
          <UserMenu />
        </div>
      </div>
      <hr />
    </div>
  );
}
