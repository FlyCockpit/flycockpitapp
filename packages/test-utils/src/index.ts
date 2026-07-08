import type { Context } from "@flycockpit/api/context";
import type { Session } from "@flycockpit/auth";
import type prismaInstance from "@flycockpit/db";
import { type DeepMockProxy, mockDeep } from "vitest-mock-extended";

/** The concrete PrismaClient type used throughout the monorepo. */
type PrismaClient = typeof prismaInstance;

/** Partial overrides for session fields. Pass `null` to simulate an unauthenticated request. */
type SessionOverride = {
  user?: Partial<Session["user"]>;
  session?: Partial<Session["session"]>;
} | null;

export type MockContext = {
  /** oRPC context — pass this to procedure handlers under test. */
  ctx: Context;
  /** Deep-mocked PrismaClient — configure return values per test. */
  db: DeepMockProxy<PrismaClient>;
};

/**
 * Build a typed oRPC context for unit tests.
 *
 * @example
 * ```ts
 * const { ctx, db } = createMockContext(); // authenticated user
 * const { ctx } = createMockContext({ session: null }); // unauthenticated
 * const { ctx } = createMockContext({ session: { user: { role: "admin" } } });
 * ```
 */
export function createMockContext(opts?: { session?: SessionOverride }): MockContext {
  const db = mockDeep<PrismaClient>();

  // Default: authenticated session with sensible test values.
  // Pass `{ session: null }` for unauthenticated context.
  const wantsNull = opts?.session === null;

  const session: Session | null = wantsNull
    ? null
    : ({
        user: {
          id: "test-user-id",
          email: "test@example.com",
          name: "Test User",
          emailVerified: true,
          role: "user",
          locale: "en-US",
          twoFactorEnabled: false,
          image: null,
          banned: false,
          banReason: null,
          banExpires: null,
          createdAt: new Date("2025-01-01"),
          updatedAt: new Date("2025-01-01"),
          ...opts?.session?.user,
        },
        session: {
          id: "test-session-id",
          userId: opts?.session?.user?.id ?? "test-user-id",
          token: "test-token",
          expiresAt: new Date(Date.now() + 86_400_000), // +24h
          ipAddress: "127.0.0.1",
          userAgent: "vitest",
          createdAt: new Date("2025-01-01"),
          updatedAt: new Date("2025-01-01"),
          ...opts?.session?.session,
        },
      } as Session);

  const ctx: Context = { session };

  return { ctx, db };
}
