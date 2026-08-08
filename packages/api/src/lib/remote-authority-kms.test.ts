import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  type AuthorityPrivateKey,
  type AuthorityRingFile,
  CachedAuthorityVerifier,
  FileAuthoritySigner,
  InjectedAuthoritySigner,
  normalizeEs256Signature,
  parseAuthorityRingFile,
} from "./remote-authority";

const ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

function key(kid: string, state: AuthorityPrivateKey["state"]) {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }),
    jwk = privateKey.export({ format: "jwk" });
  return {
    privateKey,
    value: {
      kid,
      alg: "ES256" as const,
      kty: "EC" as const,
      crv: "P-256" as const,
      x: jwk.x!,
      y: jwk.y!,
      d: jwk.d!,
      state,
      activatedAt: "1",
      retireAt: null,
    },
  };
}

function ring(keys: AuthorityPrivateKey[], currentKid: string): AuthorityRingFile {
  return parseAuthorityRingFile({
    schemaVersion: 1,
    revision: "1",
    authorityEpoch: "1",
    currentKid,
    keys: [...keys].sort((a, b) => Buffer.compare(Buffer.from(a.kid), Buffer.from(b.kid))),
  });
}

describe("remote_authority_kms_conformance", () => {
  it("normalizes provider DER and P1363 signatures without a key extraction API", async () => {
    const material = key("opaque-provider-handle", "current"),
      input = new TextEncoder().encode("provider-conformance"),
      der = sign("sha256", input, { key: material.privateKey, dsaEncoding: "der" }),
      expected = normalizeEs256Signature({ encoding: "der", bytes: der }),
      calls: Array<{ input: Uint8Array; mintId: string }> = [],
      provider = new InjectedAuthoritySigner(material.value.kid, async (bytes, mintId) => {
        calls.push({ input: bytes, mintId });
        return { encoding: "der", bytes: der };
      });
    expect(await provider.signP1363(input, "mint-stable-1")).toEqual(expected);
    expect(calls).toEqual([{ input, mintId: "mint-stable-1" }]);
    expect(Object.getOwnPropertyNames(provider)).not.toContain("privateKey");
    expect(Buffer.from(material.value.x, "base64url")).toHaveLength(32);
    expect(Buffer.from(material.value.y, "base64url")).toHaveLength(32);
    expect(Buffer.from(material.value.d, "base64url")).toHaveLength(32);
  });

  it("normalizes high-S P1363 and rejects malformed provider output", () => {
    const material = key("k0", "current"),
      input = new TextEncoder().encode("high-s"),
      low = normalizeEs256Signature({
        encoding: "ieee-p1363",
        bytes: sign("sha256", input, {
          key: material.privateKey,
          dsaEncoding: "ieee-p1363",
        }),
      }),
      high = Buffer.from(low),
      lowS = BigInt(`0x${Buffer.from(low).subarray(32).toString("hex")}`);
    high.set(Buffer.from((ORDER - lowS).toString(16).padStart(64, "0"), "hex"), 32);
    expect(normalizeEs256Signature({ encoding: "ieee-p1363", bytes: high })).toEqual(low);
    expect(() =>
      normalizeEs256Signature({ encoding: "ieee-p1363", bytes: new Uint8Array(63) }),
    ).toThrow();
    expect(() =>
      normalizeEs256Signature({ encoding: "der", bytes: new Uint8Array([0x30, 0]) }),
    ).toThrow();
  });

  it("single-flights unknown-kid refresh once per issuer per 30 seconds", async () => {
    const k0 = key("k0", "current"),
      k1 = key("k1", "current"),
      initial = ring([k0.value], "k0"),
      refreshed = ring([{ ...k0.value, state: "verification_only" }, k1.value], "k1"),
      input = new TextEncoder().encode("claims"),
      signature = await new FileAuthoritySigner(k1.value).signP1363(input, "mint-1");
    let loads = 0,
      release!: () => void;
    const gate = new Promise<void>((resolve) => {
        release = resolve;
      }),
      verifier = new CachedAuthorityVerifier(
        "https://authority.example",
        initial,
        () => 100,
        async () => {
          loads++;
          await gate;
          return refreshed;
        },
      ),
      results = [
        verifier.verifyP1363(input, signature, "k1"),
        verifier.verifyP1363(input, signature, "k1"),
        verifier.verifyP1363(input, signature, "k1"),
      ];
    await Promise.resolve();
    expect(loads).toBe(1);
    release();
    expect(await Promise.all(results)).toEqual([true, true, true]);
    expect(await verifier.verifyP1363(input, signature, "missing")).toBe(false);
    expect(loads).toBe(1);
  });
});
