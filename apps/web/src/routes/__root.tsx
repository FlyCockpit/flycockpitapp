// The bundler resolves this to the content-hashed /assets URL of the Latin
// variable Roboto subset — the one the UI actually paints (the other subsets
// stay gated behind their unicode-range). Used to <link rel="preload"> it so it
// downloads in parallel with the CSS instead of being discovered only after the
// stylesheet parses (which puts it at the tail of the critical request chain).

import { THEME_INIT_SCRIPT } from "@flycockpit/config/theme-init";
import { env } from "@flycockpit/env/web";
import { Toaster } from "@flycockpit/ui/components/sileo";
import robotoLatinUrl from "@fontsource-variable/roboto/files/roboto-latin-wght-normal.woff2?url";
import type { QueryClient } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import {
  createRootRouteWithContext,
  HeadContent,
  Outlet,
  Scripts,
  useRouterState,
} from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/react-router-devtools";
import { lazy, type ReactNode, Suspense } from "react";
import { I18nextProvider } from "react-i18next";
import { AdminSetupBanner } from "@/components/admin-setup-banner";
import BottomNav from "@/components/bottom-nav";
import { ConsentManager } from "@/components/consent/consent-manager";
import ErrorState from "@/components/error-state";
import Header from "@/components/header";
import { UserNotificationClient } from "@/components/notifications/user-notification-client";
import { LiveTerminalBanner } from "@/components/terminal/live-terminal-banner";
import { ThemeColorSync } from "@/components/theme-color-sync";
import { ThemeProvider } from "@/components/theme-provider";
import { useAppUpdate } from "@/hooks/use-app-update";
import { useDocumentLang } from "@/hooks/use-document-lang";
import { useMobileKeyboard } from "@/hooks/use-mobile-keyboard";
import { useNavDirection } from "@/hooks/use-nav-direction";
import { useUserLocaleSync } from "@/hooks/use-user-locale-sync";
import i18n from "@/i18n";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { I18nReady } from "@/i18n/I18nReady";
import { orpc } from "@/utils/orpc";

import "../index.css";

export interface RouterAppContext {
  orpc: typeof orpc;
  queryClient: QueryClient;
}

const APP_NAME = env.VITE_APP_NAME;

// Headless better-auth session bridge. Lazy so the better-auth client chunk and
// its `get-session` fetch load after first paint instead of during hydration;
// consumers read the session via `useDeferredSession()` (stores/session.ts).
const SessionSync = lazy(() => import("@/components/session-sync"));

export const Route = createRootRouteWithContext<RouterAppContext>()({
  // SPA by default. Individual routes can opt into SSR with `ssr: true` or
  // `ssr: "data-only"` — see the SSR route guidance. Keeping the
  // default as SPA avoids running `beforeLoad` auth checks on the server
  // (where browser cookies aren't available) and keeps dashboard data
  // fetching client-side with skeleton loaders.
  ssr: false,
  // shellComponent renders the document (`<html>`/`<head>`/`<body>`/`<Scripts />`)
  // server-side. It's the only piece of the root that runs on the server when
  // `ssr: false` — react-router wraps `component` in `<ClientOnly>` for ssr:false
  // routes (Match.js), so anything inside `RootComponent` is client-only. Without
  // a shellComponent, the SSR response is just a Suspense fallback with no script
  // tag, and hydration never happens.
  shellComponent: RootShell,
  component: RootComponent,
  errorComponent: ErrorState,
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      {
        name: "viewport",
        content: "width=device-width, initial-scale=1.0, viewport-fit=cover",
      },
      { name: "apple-mobile-web-app-capable", content: "yes" },
      { name: "apple-mobile-web-app-status-bar-style", content: "black" },
      { name: "mobile-web-app-capable", content: "yes" },
      // NOTE: `theme-color` is intentionally NOT declared here. It is managed
      // imperatively so it tracks the RESOLVED app theme (next-themes) rather
      // than the OS prefers-color-scheme — THEME_INIT_SCRIPT creates it on the
      // first frame and `useThemeColorMeta` updates it on in-app toggles. A
      // static media-keyed meta here would fight that and reintroduce the
      // white-status-bar-in-dark-mode bug when the OS and app themes disagree.
      {
        title: APP_NAME,
      },
      {
        name: "description",
        content: i18n.t("errors:pageDescription", { appName: APP_NAME }),
      },
    ],
    links: [
      // Preload the Latin Roboto subset to pull it out of the critical request
      // chain (HTML → CSS → @font-face → font). `crossOrigin` is required even
      // same-origin: fonts fetch in CORS mode, and an attribute mismatch with
      // the @font-face request would cause a duplicate download.
      {
        rel: "preload",
        href: robotoLatinUrl,
        as: "font",
        type: "font/woff2",
        crossOrigin: "anonymous",
      },
      {
        rel: "icon",
        href: "/favicon.ico",
      },
      { rel: "manifest", href: "/manifest.webmanifest" },
      { rel: "apple-touch-icon", sizes: "180x180", href: "/apple-touch-icon-180x180.png" },
    ],
  }),
});

function RootShell({ children }: { children: ReactNode }) {
  const lang = useRouterState({
    select: (state) => {
      const segment = state.location.pathname.split("/")[1];
      return isSupportedLocale(segment) ? segment : DEFAULT_LOCALE;
    },
  });

  return (
    <html lang={lang} style={{ colorScheme: "dark light" }}>
      <head>
        {/* Blocking anti-FOUC theme script, inlined (not an external request) so
            it runs before first paint with zero added latency on the critical
            render path. Allowed under `script-src 'self' 'nonce-…'` via a CSP
            sha256 hash derived from THEME_INIT_SCRIPT at server startup — see
            apps/server/src/index.ts. Must stay first in <head> and must NOT be
            async/defer. */}
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
        <HeadContent />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  );
}

function RootComponent() {
  useAppUpdate();
  useNavDirection();
  useDocumentLang();
  useUserLocaleSync();
  const mobileKeyboardOpen = useMobileKeyboard();

  return (
    <I18nextProvider i18n={i18n}>
      <I18nReady>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
          storageKey="vite-ui-theme"
        >
          <div
            className="grid h-svh grid-rows-[auto_1fr_auto] md:grid-rows-[auto_1fr] pb-[calc(3.5rem_+_var(--safe-area-bottom))] md:pb-0"
            style={{
              paddingTop: "var(--safe-area-top)",
              paddingLeft: "var(--safe-area-left)",
              paddingRight: "var(--safe-area-right)",
            }}
          >
            <div className={mobileKeyboardOpen ? "max-h-0 overflow-hidden" : ""}>
              <Header />
              <AdminSetupBanner />
              <LiveTerminalBanner />
            </div>
            <main style={{ viewTransitionName: "page" }} className="min-h-0 overflow-y-auto">
              <Outlet />
            </main>
            <BottomNav hidden={mobileKeyboardOpen} />
          </div>
          <ThemeColorSync />
          <Suspense fallback={null}>
            <SessionSync />
          </Suspense>
          <UserNotificationClient />
          <Toaster />
          <ConsentManager />
          {import.meta.env.DEV && (
            <>
              <TanStackRouterDevtools position="bottom-left" />
              <ReactQueryDevtools position="bottom" buttonPosition="bottom-right" />
            </>
          )}
        </ThemeProvider>
      </I18nReady>
    </I18nextProvider>
  );
}
