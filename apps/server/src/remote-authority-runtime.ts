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

export function createServerRemoteAuthority(deps: {
  env: typeof envType;
  prisma: typeof prismaType;
  redis: RedisClient;
}) {
  const snapshot = new AuthorityPublicSnapshot(),
    values = [
      deps.env.REMOTE_GRANT_SIGNING_KEY_FILE,
      deps.env.REMOTE_AUTHORITY_ISSUER,
      deps.env.REMOTE_AUTHORITY_DEPLOYMENT_ID,
      deps.env.REMOTE_GRANT_SIGNING_KEY_DIGESTS,
      deps.env.REMOTE_AUTHORITY_REPLICA_ID,
    ];
  if (values.every((value) => value === undefined)) return { snapshot, runtime: undefined };
  if (values.some((value) => value === undefined))
    throw new Error("all remote-authority environment variables must be configured together");
  const runtime = new RemoteAuthorityRuntime({
    keyFile: deps.env.REMOTE_GRANT_SIGNING_KEY_FILE!,
    issuer: deps.env.REMOTE_AUTHORITY_ISSUER!,
    deploymentId: deps.env.REMOTE_AUTHORITY_DEPLOYMENT_ID!,
    digests: deps.env.REMOTE_GRANT_SIGNING_KEY_DIGESTS!,
    replicaId: deps.env.REMOTE_AUTHORITY_REPLICA_ID!,
    leaseGeneration: crypto.randomUUID().replaceAll("-", ""),
    store: new PostgresAuthorityRuntimeStore(deps.prisma as unknown as SqlClient),
    observations: new RedisAuthorityObservationStore(deps.redis),
    snapshot,
  });
  return { snapshot, runtime };
}
