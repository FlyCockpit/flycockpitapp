import { env } from "@flycockpit/env/shared";
import IORedis from "ioredis";

/**
 * Shared Redis connection for queue producers (adding jobs).
 * Workers should create their own connection with `maxRetriesPerRequest: null`.
 */
export const redisConnection = new IORedis(env.REDIS_URL, {
  maxRetriesPerRequest: 3,
  connectTimeout: 5000,
  commandTimeout: 5000,
});

/** Create a fresh IORedis connection from the env REDIS_URL. */
export function createRedisConnection(opts?: {
  maxRetriesPerRequest?: number | null;
  connectTimeout?: number;
  commandTimeout?: number;
}) {
  return new IORedis(env.REDIS_URL, {
    maxRetriesPerRequest: opts?.maxRetriesPerRequest ?? null,
    connectTimeout: opts?.connectTimeout ?? 5000,
    commandTimeout: opts?.commandTimeout,
  });
}
