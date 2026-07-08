import {
  env,
  RELAY_ID,
  RELAY_JWKS_URL,
  RELAY_PORT,
  RELAY_TOKEN_ISSUER,
} from "@flycockpit/env/relay";
import { createRelayServer } from "./server.js";

const relay = createRelayServer({
  relayId: RELAY_ID,
  port: RELAY_PORT,
  jwksUrl: RELAY_JWKS_URL,
  tokenIssuer: RELAY_TOKEN_ISSUER,
  heartbeatMs: env.RELAY_HEARTBEAT_MS,
  leaseTtlMs: env.RELAY_LEASE_TTL_MS,
  maxFrameBytes: env.RELAY_MAX_FRAME_BYTES,
  maxChannelsPerClient: env.RELAY_MAX_CHANNELS_PER_CLIENT,
  maxConnectionsPerInstance: env.RELAY_MAX_CONNECTIONS_PER_INSTANCE,
  clientRateLimitPerSecond: env.RELAY_CLIENT_RATE_LIMIT_PER_SECOND,
  controlIngestUrl: env.RELAY_CONTROL_INGEST_URL,
  controlSecret: env.RELAY_CONTROL_SECRET,
  redisUrl: env.REDIS_URL,
});

console.log(`[relay] listening on :${RELAY_PORT} relay=${RELAY_ID} jwks=${RELAY_JWKS_URL}`);

async function shutdown(signal: string) {
  console.log(`[relay] received ${signal}, shutting down`);
  await relay.close();
  process.exit(0);
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
