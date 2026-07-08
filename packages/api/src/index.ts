import { isAdminRole } from "@flycockpit/auth/roles";
import { ORPCError, os } from "@orpc/server";

import type { Context } from "./context";
import { isTwoFactorPolicySatisfied } from "./lib/two-factor-policy";

export {
  isForcedTwoFactorEnabledForRole,
  isTwoFactorPolicySatisfied,
} from "./lib/two-factor-policy";

const o = os.$context<Context>();

export const publicProcedure = o;

const requireAuth = o.middleware(async ({ context, next }) => {
  if (!context.session?.user) {
    throw new ORPCError("UNAUTHORIZED");
  }
  return next({
    context: {
      session: context.session,
    },
  });
});

export const authenticatedProcedure = publicProcedure.use(requireAuth);

const requireRequiredTwoFactor = o.middleware(async ({ context, next }) => {
  if (!context.session?.user) {
    throw new ORPCError("UNAUTHORIZED");
  }
  if (!(await isTwoFactorPolicySatisfied(context.session.user))) {
    throw new ORPCError("FORBIDDEN", {
      message: "Two-factor authentication setup is required.",
    });
  }
  return next({
    context: {
      session: context.session,
    },
  });
});

export const protectedProcedure = authenticatedProcedure.use(requireRequiredTwoFactor);

const requireAdmin = o.middleware(async ({ context, next }) => {
  // `requireAuth` is always chained before this middleware, so session is
  // non-null at runtime — but the middleware-chain types don't carry that
  // narrowing through, so repeat the guard for the type checker.
  if (!context.session?.user) {
    throw new ORPCError("UNAUTHORIZED");
  }
  if (!context.session.user.emailVerified) {
    throw new ORPCError("FORBIDDEN", {
      message: "Email verification required for admin access.",
    });
  }
  if (!isAdminRole(context.session.user.role)) {
    throw new ORPCError("FORBIDDEN", {
      message: "Admin access required.",
    });
  }
  if (!(await isTwoFactorPolicySatisfied(context.session.user))) {
    throw new ORPCError("FORBIDDEN", {
      message: "Two-factor authentication setup is required.",
    });
  }
  return next({
    context: {
      session: context.session,
    },
  });
});

export const adminProcedure = publicProcedure.use(requireAuth).use(requireAdmin);

// `adminOr404Procedure` mirrors the role check in `requireAdmin` but throws
// NOT_FOUND for every failure mode (missing session, unverified email,
// non-admin role). Mount it on procedures that back a 404-hidden surface
// (e.g. the /admin route group) so existence of the endpoint is not leaked
// to non-admins.
const requireAdminOr404 = o.middleware(async ({ context, next }) => {
  const notFound = () => new ORPCError("NOT_FOUND", { message: "Not found" });
  if (!context.session?.user) {
    throw notFound();
  }
  if (!context.session.user.emailVerified) {
    throw notFound();
  }
  if (!isAdminRole(context.session.user.role)) {
    throw notFound();
  }
  if (!(await isTwoFactorPolicySatisfied(context.session.user))) {
    throw notFound();
  }
  return next({
    context: {
      session: context.session,
    },
  });
});

export const adminOr404Procedure = publicProcedure.use(requireAdminOr404);
