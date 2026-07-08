import { create } from "zustand";
import { useShallow } from "zustand/react/shallow";

import type { authClient } from "@/lib/auth-client";

// The shape of better-auth's `useSession().data` (user + session, or null when
// signed out). Inferred from the client so additional fields like `user.locale`
// (inferAdditionalFields) stay typed. `import type` keeps the better-auth
// runtime OUT of this eager store chunk — the live session is fed in by the
// lazily-mounted SessionSync bridge, not read here.
type SessionData = ReturnType<typeof authClient.useSession>["data"];

interface SessionState {
  data: SessionData;
  isPending: boolean;
  setSession: (data: SessionData, isPending: boolean) => void;
}

export const useSessionStore = create<SessionState>()((set) => ({
  // Starts pending: the bridge hasn't mounted yet, so consumers render their
  // neutral pending state (skeleton / nothing) instead of a "signed out" flash
  // on an authenticated reload. Resolves once SessionSync feeds the real value.
  data: null,
  isPending: true,
  setSession: (data, isPending) => set({ data, isPending }),
}));

/**
 * Deferred drop-in for `authClient.useSession()`. Reads the session from a
 * store that the lazily-mounted `SessionSync` bridge populates AFTER first
 * paint, so the better-auth client chunk and its `get-session` fetch no longer
 * sit on the initial hydration path. Returns `{ data, isPending }` with the
 * same meaning as better-auth's hook.
 */
export function useDeferredSession() {
  return useSessionStore(useShallow((s) => ({ data: s.data, isPending: s.isPending })));
}
