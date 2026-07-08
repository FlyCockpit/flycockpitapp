import { env } from "@flycockpit/env/server";
import {
  createRelayKeySet,
  type RelayTokenInput,
  type RelayTokenPayload,
  signRelayToken,
  verifyRelayTokenWithSecret,
} from "@flycockpit/relay-protocol/tokens";

export type { RelayGrant, RelayGrantScope, RelayTokenPayload } from "@flycockpit/relay-protocol";
export { RELAY_AUDIENCE, RELAY_TOKEN_TTL_SECONDS } from "@flycockpit/relay-protocol/tokens";

export function getRelayJwks() {
  return createRelayKeySet(env.BETTER_AUTH_SECRET).jwks;
}

export async function createRelayToken(
  payload: RelayTokenInput,
  ttlSeconds?: number,
): Promise<{ token: string; expiresAt: Date; payload: RelayTokenPayload }> {
  return signRelayToken(payload, {
    secret: env.BETTER_AUTH_SECRET,
    issuer: env.BETTER_AUTH_URL,
    ttlSeconds,
  });
}

export async function verifyRelayToken(token: string): Promise<RelayTokenPayload> {
  return verifyRelayTokenWithSecret(token, {
    secret: env.BETTER_AUTH_SECRET,
    issuer: env.BETTER_AUTH_URL,
  });
}
