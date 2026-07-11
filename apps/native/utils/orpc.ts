import type { AppRouterClient } from "@flycockpit/api/routers/index";
import { env } from "@flycockpit/env/native";
import { createORPCClient } from "@orpc/client";
import { RPCLink } from "@orpc/client/fetch";
import { SimpleCsrfProtectionLinkPlugin } from "@orpc/client/plugins";
import { createTanstackQueryUtils } from "@orpc/tanstack-query";
import { QueryCache, QueryClient } from "@tanstack/react-query";
import { Platform } from "react-native";

import { authClient } from "@/lib/auth-client";

let cachedCookie: string | null | undefined;

authClient.$store.listen("$sessionSignal", () => {
  cachedCookie = undefined;
});

function getSessionCookie(): string | null {
  if (cachedCookie !== undefined) return cachedCookie;
  cachedCookie = authClient.getCookie() || null;
  return cachedCookie;
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      gcTime: 5 * 60_000,
      retry: 1,
      staleTime: 30_000,
    },
  },
  queryCache: new QueryCache({
    onError: (error) => {
      console.log(error);
    },
  }),
});

const link = new RPCLink({
  url: `${env.EXPO_PUBLIC_SERVER_URL}/rpc`,
  plugins: [new SimpleCsrfProtectionLinkPlugin()],
  fetch: (url, options) =>
    fetch(url, {
      ...options,
      // Better Auth Expo forwards the session cookie manually on native.
      credentials: Platform.OS === "web" ? "include" : "omit",
    }),
  headers() {
    if (Platform.OS === "web") {
      return {};
    }
    const headers = new Map<string, string>();
    const cookies = getSessionCookie();
    if (cookies) {
      headers.set("Cookie", cookies);
    }
    return Object.fromEntries(headers);
  },
});

const client: AppRouterClient = createORPCClient(link);

export const orpc = createTanstackQueryUtils(client);

export function appConfigQueryOptions() {
  return {
    ...orpc.appConfig.queryOptions(),
    staleTime: 5 * 60_000,
  };
}
