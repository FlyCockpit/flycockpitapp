import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";

import { useChangeLanguage } from "@/hooks/use-change-language";
import { decideLocaleRedirect } from "@/i18n/redirect-to-default";

/**
 * Locale-prefix layout. Every URL in the app lives under `/$lang/...` —
 * this route validates the param, swaps i18next's active language, and
 * renders an `<Outlet />` for the nested page.
 *
 * Validation contract:
 *  - `params.lang` is a supported locale (en-US, es-MX, …) → render.
 *  - `params.lang` is anything else (a missing-prefix path like `/dashboard`,
 *    or an unknown locale like `/xx-XX/about`) → 302 to `/${DEFAULT_LOCALE}`
 *    plus the rest of the URL, preserving search + hash.
 *
 * The redirect logic is in `i18n/redirect-to-default.ts` so the
 * decision-making is unit-testable without dragging in React-only modules.
 */
export const Route = createFileRoute("/$lang")({
  beforeLoad: ({ params, location }) => {
    const instruction = decideLocaleRedirect({ params, location });
    if (instruction) throw redirect(instruction);
  },
  component: LangLayout,
});

function LangLayout() {
  const { lang } = Route.useParams();
  useChangeLanguage(lang);
  return <Outlet />;
}
