import { toast } from "@flycockpit/ui/components/sileo";
import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";
import { createRouter } from "@tanstack/react-router";
import { setupRouterSsrQueryIntegration } from "@tanstack/react-router-ssr-query";
import { createIsomorphicFn } from "@tanstack/react-start";
import { getRequestHeader } from "@tanstack/react-start/server";

import ErrorState from "./components/error-state";
import Loader from "./components/loader";
import i18n from "./i18n";
import { getPageViewTransitionTypes } from "./lib/view-transition-policy";
import { routeTree } from "./routeTree.gen";
import { friendly } from "./utils/friendly-error";
import { orpc } from "./utils/orpc";

// Read the per-request CSP nonce forwarded by the API server on the
// `x-csp-nonce` request header (set in apps/server/src/index.ts). Server-only:
// createIsomorphicFn strips the `.server()` branch — and its server-only
// import — from the client bundle, so this is safe in this shared module.
const getCspNonce = createIsomorphicFn()
  .server(() => getRequestHeader("x-csp-nonce") ?? undefined)
  .client(() => undefined);

export function getRouter() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { staleTime: 1000 * 60 * 5 },
    },
    queryCache: new QueryCache({
      onError: (error, query) => {
        toast.error(friendly(error), {
          action: {
            label: "retry",
            onClick: query.invalidate,
          },
        });
      },
    }),
    mutationCache: new MutationCache({
      // Surface mutation failures by default so no action ever fails silently.
      // Mutations that handle their own errors (e.g. inline form errors) can
      // opt out with `useMutation({ meta: { skipGlobalErrorToast: true } })`.
      // Mutations that just want context-specific fallback copy (instead of the
      // generic "Something didn't work") set
      // `meta: { errorFallbackKey: "ns:key" }` — no per-call onError toast.
      onError: (error, _vars, _ctx, mutation) => {
        if (mutation.meta?.skipGlobalErrorToast) return;
        const fallback = mutation.meta?.errorFallbackKey
          ? i18n.t(mutation.meta.errorFallbackKey)
          : undefined;
        toast.error(friendly(error, fallback));
      },
    }),
  });

  const router = createRouter({
    routeTree,
    defaultPreload: "intent",
    defaultPreloadStaleTime: 0,
    // Page View Transitions are for screen changes. Same-path query/hash/state
    // updates are in-place state changes and should render instantly.
    defaultViewTransition: {
      types: getPageViewTransitionTypes,
    },
    defaultPendingComponent: () => <Loader />,
    defaultErrorComponent: ErrorState,
    context: { orpc, queryClient },
    scrollRestoration: true,
    // CSP nonce for SSR-injected inline scripts (hydration, etc.). Matches the
    // nonce in the script-src CSP header set by the API server. undefined on
    // the client (the document already carries the server-rendered nonce).
    ssr: { nonce: getCspNonce() },
  });

  setupRouterSsrQueryIntegration({ router, queryClient });

  return router;
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof getRouter>;
  }
}

declare module "@tanstack/react-query" {
  interface Register {
    mutationMeta: {
      /** Suppress the global error toast for this mutation. */
      skipGlobalErrorToast?: boolean;
      /**
       * i18n key resolved (outside React, via the app i18n instance) and
       * passed to `friendly()` as the context-specific fallback copy for the
       * global error toast. Use this instead of a per-call `onError` that only
       * called `toast.error(friendly(err, t("ns:key")))`.
       */
      errorFallbackKey?: string;
    };
  }
}
