import { AuthorityPublicSnapshot } from "@flycockpit/api/lib/remote-authority";
import { RemoteAuthorityRuntime } from "@flycockpit/api/lib/remote-authority-runtime";
import {
  PostgresAuthorityRuntimeStore,
  RedisAuthorityObservationStore,
  type RedisClient,
  type SqlClient,
} from "@flycockpit/api/lib/remote-authority-storage";
import type prismaType from "@flycockpit/db";
import type { env as envType } from "@flycockpit/env/server";

/**
 * Result of wiring the server's remote authority.
 * - `runtime` present → authority is active; readiness follows its rollout decision.
 * - `runtime` undefined + `disabled: true` → authority is *explicitly* off for a
 *   non-production-shaped (OSS/local) deployment. Grant minting fails closed at its
 *   own gates; readiness reports `"disabled"` rather than a silent healthy `true`.
 * - `runtime` undefined + `disabled: false` → authority is required for this
 *   deployment profile but unconfigured; readiness fails closed.
 */
export type ServerRemoteAuthority =
  | { snapshot: AuthorityPublicSnapshot; runtime: RemoteAuthorityRuntime; disabled: false }
  | { snapshot: AuthorityPublicSnapshot; runtime: undefined; disabled: boolean };

/**
 * Derive the `/ready` authority check from the wiring result. Never silently `true`
 * for a missing runtime: an active runtime follows its own readiness decision, an
 * explicitly-disabled deployment reports `"disabled"` (ok), and a required-but-missing
 * runtime reports `false` (fails closed → 503).
 */
export function authorityReadiness(authority: ServerRemoteAuthority): boolean | "disabled" {
  if (authority.runtime) return authority.runtime.decision.ready;
  return authority.disabled ? "disabled" : false;
}

export function createServerRemoteAuthority(deps: {
  env: typeof envType;
  prisma: typeof prismaType;
  redis: RedisClient;
}): ServerRemoteAuthority {
  const snapshot = new AuthorityPublicSnapshot(),
    values = [
      deps.env.REMOTE_GRANT_SIGNING_KEY_FILE,
      deps.env.REMOTE_AUTHORITY_ISSUER,
      deps.env.REMOTE_AUTHORITY_DEPLOYMENT_ID,
      deps.env.REMOTE_GRANT_SIGNING_KEY_DIGESTS,
      deps.env.REMOTE_AUTHORITY_REPLICA_ID,
    ];
  if (values.every((value) => value === undefined)) {
    if (deps.env.NODE_ENV === "production")
      throw new Error("remote authority configuration is required in production");
    // Production-shaped profiles (hosted/enterprise) mint remote grants and MUST
    // NOT report a healthy authority by default when signing is unconfigured — the
    // readiness check fails closed (`disabled: false`). Only the OSS/local profile
    // may run with the authority explicitly disabled (`disabled: true`). The caller
    // logs the chosen mode at startup (this module stays free of console output —
    // see remote-authority-static.test.ts).
    return { snapshot, runtime: undefined, disabled: deps.env.DEPLOYMENT_PROFILE === "oss" };
  }
  if (values.some((value) => value === undefined))
    throw new Error("all remote-authority environment variables must be configured together");
  const runtime = new RemoteAuthorityRuntime({
    keyFile: deps.env.REMOTE_GRANT_SIGNING_KEY_FILE!,
    issuer: deps.env.REMOTE_AUTHORITY_ISSUER!,
    deploymentId: deps.env.REMOTE_AUTHORITY_DEPLOYMENT_ID!,
    digests: deps.env.REMOTE_GRANT_SIGNING_KEY_DIGESTS!,
    replicaId: deps.env.REMOTE_AUTHORITY_REPLICA_ID!,
    store: new PostgresAuthorityRuntimeStore(deps.prisma as unknown as SqlClient),
    observations: new RedisAuthorityObservationStore(deps.redis),
    snapshot,
  });
  return { snapshot, runtime, disabled: false };
}
