import { authClient } from "@/lib/auth-client";
import { type AuthSessionState, getAuthSessionState } from "@/lib/auth-session-state";
import { useNetworkStatus } from "./use-network-status";

export function useAuthSession(): AuthSessionState {
  const session = authClient.useSession();
  const isOnline = useNetworkStatus();
  return getAuthSessionState({
    data: session.data ?? null,
    isPending: session.isPending,
    isRefetching: session.isRefetching,
    error: session.error ?? null,
    isOnline,
    refetch: session.refetch,
  });
}

export function useAuthSessionSnapshot() {
  const authSession = useAuthSession();
  return {
    data: authSession.state.status === "authenticated" ? authSession.state.session : null,
    isPending: authSession.state.status === "pending",
    isError: authSession.state.status === "error",
    refetch: authSession.actions.refetch,
  };
}
