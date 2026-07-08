import { useEffect } from "react";

import { authClient } from "@/lib/auth-client";
import { useSessionStore } from "@/stores/session";

/**
 * Subscribes to the real better-auth session and mirrors it into
 * `useSessionStore`. Lives in `hooks/` (the sanctioned `useEffect` location)
 * and is imported ONLY by the lazily-loaded `SessionSync` component, so the
 * better-auth client chunk it pulls in stays off the eager bundle. This single
 * subscription is the app's one `authClient.useSession()` call in the root
 * tree — every consumer reads the mirrored value via `useDeferredSession()`.
 */
export function useSessionBridge(): void {
  const { data, isPending } = authClient.useSession();
  const setSession = useSessionStore((s) => s.setSession);

  useEffect(() => {
    setSession(data ?? null, isPending);
  }, [data, isPending, setSession]);
}
