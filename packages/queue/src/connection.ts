import { env } from "@flycockpit/env/shared";
import IORedis from "ioredis";

/**
 * Shared Redis connection for queue producers (adding jobs).
 * Workers should create their own connection with `maxRetriesPerRequest: null`.
 */
let sharedConnection: IORedis | undefined;

/** Lazily obtain the process-owned producer connection. Importing this module opens no socket. */
export function getRedisConnection(): IORedis {
  sharedConnection ??= createRedisConnection({ maxRetriesPerRequest: 3, commandTimeout: 5000 });
  return sharedConnection;
}

/** Close and forget the process-owned connection (also deterministic in tests). */
export async function closeRedisConnection(): Promise<void> {
  const connection = sharedConnection;
  sharedConnection = undefined;
  if (connection) await connection.quit();
}

/** Forget the shared client without I/O; intended for injected unit-test doubles. */
export function resetRedisConnectionForTests(): void {
  sharedConnection?.disconnect();
  sharedConnection = undefined;
}

/** Create a fresh IORedis connection from the env REDIS_URL. */
export function createRedisConnection(opts?: {
  url?: string;
  maxRetriesPerRequest?: number | null;
  connectTimeout?: number;
  commandTimeout?: number;
}) {
  const url = opts?.url ?? env.REDIS_URL;
  return new IORedis(url, {
    maxRetriesPerRequest: opts?.maxRetriesPerRequest ?? null,
    connectTimeout: opts?.connectTimeout ?? 5000,
    commandTimeout: opts?.commandTimeout,
  });
}
