import type { authClient } from "./auth-client";

type BetterAuthSessionSnapshot = ReturnType<typeof authClient.useSession>;

type AuthSession = NonNullable<BetterAuthSessionSnapshot["data"]>;
type AuthSessionRefetch = BetterAuthSessionSnapshot["refetch"];

type AuthSessionActions = {
  refetch: AuthSessionRefetch;
  retry: AuthSessionRefetch;
};

type AuthSessionMeta = {
  isRefetching: boolean;
  isOffline: boolean;
  isDegraded: boolean;
};

type AuthSessionStateValue<TSession> =
  | { status: "pending" }
  | { status: "authenticated"; session: TSession }
  | { status: "anonymous" }
  | { status: "error" };

export type AuthSessionState<TSession = AuthSession> = {
  state: AuthSessionStateValue<TSession>;
  actions: AuthSessionActions;
  meta: AuthSessionMeta;
};

export type AuthSessionStateInput<TSession> = {
  data: TSession | null;
  isPending: boolean;
  isRefetching: boolean;
  error: unknown | null;
  isOnline: boolean;
  refetch: AuthSessionRefetch;
};

function isUnauthorizedError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "status" in error && error.status === 401;
}

export function getAuthSessionState<TSession>(
  input: AuthSessionStateInput<TSession>,
): AuthSessionState<TSession> {
  const hasConfirmedIdentity = input.data !== null;
  const isOffline = !input.isOnline;
  const actions = { refetch: input.refetch, retry: input.refetch };
  const meta = {
    isRefetching: input.isRefetching,
    isOffline,
    isDegraded: hasConfirmedIdentity && (input.error !== null || isOffline),
  };

  if (input.data !== null) {
    return { state: { status: "authenticated", session: input.data }, actions, meta };
  }

  if (isUnauthorizedError(input.error)) {
    return { state: { status: "anonymous" }, actions, meta };
  }

  if (input.error !== null) {
    return { state: { status: "error" }, actions, meta };
  }

  if (input.isPending) {
    return { state: { status: "pending" }, actions, meta };
  }

  return { state: { status: "anonymous" }, actions, meta };
}
