import { createFileRoute, redirect } from "@tanstack/react-router";

import { getInitialLocale } from "@/i18n";

/**
 * Bare `/` lands the visitor at `/${detected-locale}/`. The actual home page
 * lives at `routes/$lang/index.tsx`; this file exists solely to bounce the
 * locale-less URL through the i18n detection chain (URL → localStorage →
 * navigator → DEFAULT_LOCALE).
 */
export const Route = createFileRoute("/")({
  beforeLoad: () => {
    throw redirect({
      to: "/$lang",
      params: { lang: getInitialLocale() },
      replace: true,
    });
  },
});
