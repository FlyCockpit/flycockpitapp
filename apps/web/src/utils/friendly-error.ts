/**
 * Map an unknown error (oRPC ORPCError, fetch error, thrown Error) to safe
 * user-facing copy. Never returns `error.message` — that may contain raw
 * Prisma / auth.api / third-party SDK strings. See the error-message policy.
 *
 * Pass an optional `fallback` for context-specific copy ("Couldn't update
 * that user. Try again."). It is used only when we have no specific code
 * mapping; known codes (CONFLICT, FORBIDDEN, …) still return their mapped
 * copy.
 */
export function friendly(error: unknown, fallback?: string): string {
  const e = asErrorShape(error);
  const generic = fallback ?? "Something didn't work. Try again.";

  if (!e) return generic;

  if (e.code === "TOO_MANY_REQUESTS" || e.status === 429) {
    const retryAfter = getRetryAfter(e);
    return retryAfter !== null
      ? `Too many attempts. Try again in ${retryAfter} seconds.`
      : "Too many attempts. Please wait a few minutes and try again.";
  }

  if (e.code === "UNAUTHORIZED" || e.status === 401) {
    return "Your session has ended. Sign in again.";
  }
  if (e.code === "FORBIDDEN" || e.status === 403) {
    return "You don't have access to this.";
  }
  if (e.code === "NOT_FOUND" || e.status === 404) {
    return "That wasn't found.";
  }
  if (e.code === "CONFLICT" || e.status === 409) {
    return "That conflicts with an existing record.";
  }
  if (e.code === "BAD_REQUEST" || e.status === 400) {
    return "That request wasn't valid.";
  }
  if (e.code === "INTERNAL_SERVER_ERROR" || (typeof e.status === "number" && e.status >= 500)) {
    return fallback ?? "Something didn't work on our end. Try again in a moment.";
  }

  return generic;
}

/**
 * True if the error looks like a 429 / TOO_MANY_REQUESTS response from oRPC.
 */
export function isRateLimit(error: unknown): boolean {
  const e = asErrorShape(error);
  if (!e) return false;
  return e.status === 429 || e.code === "TOO_MANY_REQUESTS";
}

type ErrorShape = {
  status?: number;
  code?: string;
  data?: unknown;
  cause?: unknown;
  message?: string;
};

function asErrorShape(error: unknown): ErrorShape | null {
  if (!error || typeof error !== "object") return null;
  return error as ErrorShape;
}

function getRetryAfter(e: ErrorShape): number | null {
  const fromData =
    e.data && typeof e.data === "object" && "retryAfter" in e.data
      ? (e.data as { retryAfter?: unknown }).retryAfter
      : undefined;
  const fromCause =
    e.cause && typeof e.cause === "object" && "retryAfter" in e.cause
      ? (e.cause as { retryAfter?: unknown }).retryAfter
      : undefined;
  const raw = fromData ?? fromCause;
  const n = typeof raw === "number" ? raw : typeof raw === "string" ? Number(raw) : Number.NaN;
  return Number.isFinite(n) && n > 0 ? Math.ceil(n) : null;
}
