import { createECDH, createHash, randomUUID } from "node:crypto";
import {
  createRemoteJWKSet,
  importJWK,
  type JWK,
  type JWTPayload,
  type JWTVerifyGetKey,
  jwtVerify,
  SignJWT,
} from "jose";
import { z } from "zod";
import { type RelayGrant, relayGrantSchema } from "./envelopes";

export const RELAY_TOKEN_TTL_SECONDS = 5 * 60;
export const RELAY_TOKEN_ALG = "ES256" as const;

const curve = "prime256v1";
const derivationContext = "flycockpit-relay-token-es256-v1";

type RelayTokenType = "connector" | "client" | "user";

const basePayloadSchema = z
  .object({
    iss: z.string().min(1),
    aud: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
    tokenType: z.enum(["connector", "client", "user"]),
    instanceId: z.string().min(1).optional(),
    userId: z.string().min(1),
    grants: z.array(relayGrantSchema).default([]),
    iat: z.number().int().nonnegative(),
    exp: z.number().int().positive(),
    jti: z.string().min(1),
  })
  .passthrough();

export const relayTokenPayloadSchema = basePayloadSchema.superRefine((payload, ctx) => {
  if (
    (payload.tokenType === "connector" || payload.tokenType === "client") &&
    !payload.instanceId
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["instanceId"],
      message: payload.tokenType + " relay tokens require an instanceId",
    });
  }
  if (payload.tokenType === "connector" && payload.grants.length > 0) {
    ctx.addIssue({
      code: "custom",
      path: ["grants"],
      message: "connector relay tokens cannot carry client grants",
    });
  }
  if (payload.tokenType === "user" && payload.instanceId) {
    ctx.addIssue({
      code: "custom",
      path: ["instanceId"],
      message: "user relay tokens are not instance-scoped",
    });
  }
});
export type RelayTokenPayload = z.infer<typeof relayTokenPayloadSchema>;

export type RelayTokenInput = {
  tokenType: RelayTokenType;
  instanceId?: string;
  userId: string;
  grants?: RelayGrant[];
};

export type RelayKeySet = {
  kid: string;
  publicJwk: JWK;
  privateJwk: JWK;
  jwks: { keys: JWK[] };
};

function b64url(bytes: Buffer | Uint8Array) {
  return Buffer.from(bytes).toString("base64url");
}

function derivePrivateScalar(secret: string) {
  for (let counter = 0; counter < 100; counter += 1) {
    const candidate = createHash("sha256")
      .update(derivationContext)
      .update("\0")
      .update(secret)
      .update("\0")
      .update(String(counter))
      .digest();
    const ecdh = createECDH(curve);
    try {
      ecdh.setPrivateKey(candidate);
      return { privateKey: candidate, publicKey: ecdh.getPublicKey(undefined, "uncompressed") };
    } catch {
      // Try the next digest if the candidate is outside the curve order.
    }
  }
  throw new Error("Unable to derive a relay signing key from BETTER_AUTH_SECRET.");
}

export function createRelayKeySet(secret: string): RelayKeySet {
  if (secret.length < 32) {
    throw new Error("Relay token signing requires a secret with at least 32 characters.");
  }
  const { privateKey, publicKey } = derivePrivateScalar(secret);
  if (publicKey.length !== 65 || publicKey[0] !== 4) {
    throw new Error("Unexpected P-256 public key encoding.");
  }
  const x = b64url(publicKey.subarray(1, 33));
  const y = b64url(publicKey.subarray(33, 65));
  const kid = b64url(
    createHash("sha256")
      .update("relay:" + x + "." + y)
      .digest(),
  ).slice(0, 32);
  const publicJwk: JWK = { kty: "EC", crv: "P-256", x, y, alg: RELAY_TOKEN_ALG, use: "sig", kid };
  const privateJwk: JWK = { ...publicJwk, d: b64url(privateKey) };
  return { kid, publicJwk, privateJwk, jwks: { keys: [publicJwk] } };
}

export async function signRelayToken(
  input: RelayTokenInput,
  options: { secret: string; issuer: string; audience: string; ttlSeconds?: number; now?: Date },
): Promise<{ token: string; expiresAt: Date; payload: RelayTokenPayload }> {
  const ttlSeconds = options.ttlSeconds ?? RELAY_TOKEN_TTL_SECONDS;
  const nowSeconds = Math.floor((options.now?.getTime() ?? Date.now()) / 1000);
  const expiresAt = new Date((nowSeconds + ttlSeconds) * 1000);
  const keySet = createRelayKeySet(options.secret);
  const privateKey = await importJWK(keySet.privateJwk, RELAY_TOKEN_ALG);
  const claims = {
    tokenType: input.tokenType,
    instanceId: input.instanceId,
    userId: input.userId,
    grants: input.grants ?? [],
  } satisfies Partial<RelayTokenPayload>;
  const jti = randomUUID();
  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: RELAY_TOKEN_ALG, typ: "JWT", kid: keySet.kid })
    .setIssuer(options.issuer)
    .setAudience(options.audience)
    .setIssuedAt(nowSeconds)
    .setExpirationTime(nowSeconds + ttlSeconds)
    .setJti(jti)
    .sign(privateKey);
  const payload = relayTokenPayloadSchema.parse({
    ...claims,
    iss: options.issuer,
    aud: options.audience,
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
    jti,
  });
  return { token, expiresAt, payload };
}

export async function verifyRelayTokenWithKey(
  token: string,
  getKey: JWTVerifyGetKey,
  options: { issuer: string; audience: string },
): Promise<RelayTokenPayload> {
  const result = await jwtVerify<JWTPayload>(token, getKey, {
    issuer: options.issuer,
    audience: options.audience,
  });
  return relayTokenPayloadSchema.parse(result.payload);
}

export function createRemoteRelayTokenVerifier(options: {
  jwksUrl: string;
  issuer: string;
  audience: string;
}) {
  const jwks = createRemoteJWKSet(new URL(options.jwksUrl));
  return (token: string) =>
    verifyRelayTokenWithKey(token, jwks, { issuer: options.issuer, audience: options.audience });
}

export async function verifyRelayTokenWithSecret(
  token: string,
  options: { secret: string; issuer: string; audience: string },
): Promise<RelayTokenPayload> {
  const keySet = createRelayKeySet(options.secret);
  const publicKey = await importJWK(keySet.publicJwk, RELAY_TOKEN_ALG);
  return verifyRelayTokenWithKey(token, () => publicKey, {
    issuer: options.issuer,
    audience: options.audience,
  });
}
