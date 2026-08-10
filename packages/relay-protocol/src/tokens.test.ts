import { decodeProtectedHeader, errors, importJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
  createRelayKeySet,
  RELAY_TOKEN_ALG,
  relayTokenPayloadSchema,
  signRelayToken,
  verifyRelayTokenWithSecret,
} from "./tokens";

const secret = "1234567890abcdef1234567890abcdef";
const issuer = "https://app.example.test";

async function signWrongAudienceToken() {
  const keySet = createRelayKeySet(secret);
  const privateKey = await importJWK(keySet.privateJwk, RELAY_TOKEN_ALG);
  return new SignJWT({ tokenType: "client", instanceId: "i1", userId: "u1", grants: [] })
    .setProtectedHeader({ alg: RELAY_TOKEN_ALG, kid: keySet.kid })
    .setIssuer(issuer)
    .setAudience("relay-b")
    .setIssuedAt()
    .setExpirationTime("5m")
    .setJti("relay-b")
    .sign(privateKey);
}

describe("relay token signing", () => {
  const actorBinding = {
    schemaVersion: 1 as const,
    deviceId: "00000000-0000-4000-8000-000000000001",
    deviceGeneration: "18446744073709551615",
    logicalAttachmentId: "00000000-0000-4000-8000-000000000002",
  };

  it("stamps the exact authorized actor binding and rejects it on non-client tokens", async () => {
    const signed = await signRelayToken(
      { tokenType: "client", instanceId: "i1", userId: "u1", actorBinding },
      { secret, issuer, audience: "relay-a" },
    );
    expect(signed.payload.actorBinding).toEqual(actorBinding);
    for (const tokenType of ["connector", "user"] as const) {
      expect(() =>
        relayTokenPayloadSchema.parse({
          ...signed.payload,
          tokenType,
          instanceId: tokenType === "connector" ? "i1" : undefined,
        }),
      ).toThrow();
    }
  });
  it("signs ES256 JWTs with a public JWKS-compatible key id", async () => {
    const result = await signRelayToken(
      { tokenType: "client", instanceId: "i1", userId: "u1" },
      { secret, issuer, audience: "relay-a" },
    );
    const header = decodeProtectedHeader(result.token);

    expect(header.alg).toBe(RELAY_TOKEN_ALG);
    expect(header.kid).toBe(createRelayKeySet(secret).kid);
    await expect(
      verifyRelayTokenWithSecret(result.token, { secret, issuer, audience: "relay-a" }),
    ).resolves.toMatchObject({
      aud: "relay-a",
      tokenType: "client",
      instanceId: "i1",
      userId: "u1",
    });
  });

  it("accepts string and array audiences in the payload schema", () => {
    const base = {
      iss: issuer,
      tokenType: "client",
      instanceId: "i1",
      userId: "u1",
      grants: [],
      iat: 1,
      exp: 2,
      jti: "jti-1",
    };

    expect(relayTokenPayloadSchema.parse({ ...base, aud: "relay-a" }).aud).toBe("relay-a");
    expect(relayTokenPayloadSchema.parse({ ...base, aud: ["relay-a"] }).aud).toEqual(["relay-a"]);
    expect(() => relayTokenPayloadSchema.parse({ ...base, aud: "" })).toThrow();
  });

  it("rejects expired, garbage, and wrong-audience tokens", async () => {
    const expired = await signRelayToken(
      { tokenType: "connector", instanceId: "i1", userId: "u1" },
      { secret, issuer, audience: "relay-a", ttlSeconds: -1 },
    );
    await expect(
      verifyRelayTokenWithSecret(expired.token, { secret, issuer, audience: "relay-a" }),
    ).rejects.toBeInstanceOf(errors.JWTExpired);
    await expect(
      verifyRelayTokenWithSecret("not-a-jwt", { secret, issuer, audience: "relay-a" }),
    ).rejects.toThrow();
    await expect(
      verifyRelayTokenWithSecret(await signWrongAudienceToken(), {
        secret,
        issuer,
        audience: "relay-a",
      }),
    ).rejects.toThrow();
  });
});
