import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  decodePossessionProof,
  encodePossessionProof,
  type PossessionPurposeV1,
  possessionProofSigningMessage,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import { RemoteNativeIdentityCustodyError } from "./remote-native-identity-custody";
import {
  FakeRemoteIdentityCustodyModule,
  normalizeLowSP1363,
} from "./remote-native-identity-custody.test-support";

const FIXTURE = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "..",
      "..",
      "packages",
      "cockpit-protocol",
      "fixtures",
      "remote-identity-custody-signing-v1.json",
    ),
    "utf-8",
  ),
) as {
  purpose: number;
  subjectKind: number;
  unsignedProof: string;
  message: string;
  publicKey: { x: string; y: string };
  signatureLowS: string;
  signatureHighS: string;
};

// P-256 half-order n/2 — the actual low-S boundary the production codec enforces.
const P256_HALF_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n >> 1n;

function sScalar(signature: Uint8Array): bigint {
  return signature.slice(32, 64).reduce((acc, b) => (acc << 8n) | BigInt(b), 0n);
}

/**
 * Prove a signature is canonical low-S through the PRODUCTION codec: assemble a
 * full 239-byte proof and require `decodePossessionProof` to accept it (its
 * validateLowSP1363 gate rejects any `s > n/2`), then assert `s <= n/2` against
 * the real P-256 half-order — never a bit-7 heuristic.
 */
function assertLowSViaCodec(unsigned: Uint8Array, signature: Uint8Array): void {
  const proof = new Uint8Array(239);
  proof.set(unsigned);
  proof.set(signature, 175);
  decodePossessionProof(proof);
  expect(sScalar(signature) <= P256_HALF_ORDER).toBe(true);
}

// ---------------------------------------------------------------------------
// The conformance fake implements the module's exact five-method interface with
// real WebCrypto P-256 keys.
// ---------------------------------------------------------------------------

const handle = (fill: number) => new Uint8Array(16).fill(fill);

describe("remote_identity_custody_fake_conformance", () => {
  it("exposes exactly the five native methods", () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const names = ["generateP256", "signP256", "publicKey", "rotateP256", "destroyGeneration"];
    for (const name of names) {
      expect(typeof (module as unknown as Record<string, unknown>)[name]).toBe("function");
    }
  });

  it("generate returns a 16-byte nonzero handle, 32-byte public coordinates, and evidence", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const result = await module.generateP256(handle(0x1a), "ios-secure-enclave", false);
    expect(result.handleId.length).toBe(16);
    expect(result.handleId.some((b) => b !== 0)).toBe(true);
    expect(result.publicKey.x.length).toBe(32);
    expect(result.publicKey.y.length).toBe(32);
    expect(result.providerEvidence.length).toBeGreaterThan(0);
    expect(result.attestation.securityLevel).toBe("secure_enclave");
  });

  it("publicKey and reopen-by-sign require a known handle", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    await expect(module.publicKey(new Uint8Array(16).fill(9))).rejects.toBeInstanceOf(
      RemoteNativeIdentityCustodyError,
    );
    await expect(
      module.signP256(new Uint8Array(16).fill(9), new Uint8Array(32)),
    ).rejects.toMatchObject({ code: "not_found" });
  });

  it("rotate mints a fresh handle while retaining the old key until destroyed", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const original = await module.generateP256(handle(0x1a), "android-strongbox", false);
    const rotated = await module.rotateP256(original.handleId, handle(0x2b));
    expect(module.size).toBe(2);
    expect([...rotated.handleId].join(",")).not.toBe([...original.handleId].join(","));
    await module.destroyGeneration(original.handleId);
    expect(module.size).toBe(1);
  });

  it("signs low-S: repeated signatures pass the production codec with s <= n/2", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const gen = await module.generateP256(handle(0x3c), "ios-keychain", false);
    const unsigned = fromHex(FIXTURE.unsignedProof);
    const message = fromHex(FIXTURE.message);
    // Route MANY randomized signatures through encode/decodePossessionProof and
    // assert s <= half-order each time — deleting normalization fails ~half the
    // time here, unlike a bit-7 check.
    for (let i = 0; i < 32; i++) {
      const sig = await module.signP256(gen.handleId, message);
      expect(sig.length).toBe(64);
      assertLowSViaCodec(unsigned, sig);
    }
  });

  it("normalizes a KNOWN high-S value to the codec-accepted low-S form", () => {
    const unsigned = fromHex(FIXTURE.unsignedProof);
    const highS = fromHex(FIXTURE.signatureHighS);
    const lowS = fromHex(FIXTURE.signatureLowS);
    // The pinned high-S signature is REJECTED by the production codec...
    const highProof = new Uint8Array(239);
    highProof.set(unsigned);
    highProof.set(highS, 175);
    expect(() => decodePossessionProof(highProof)).toThrow();
    // ...and normalizing it yields exactly the low-S form the codec accepts.
    const normalized = normalizeLowSP1363(highS);
    expect([...normalized]).toEqual([...lowS]);
    assertLowSViaCodec(unsigned, normalized);
  });

  it("rejects a zero or out-of-range signature component as corrupted", () => {
    // zero-s
    expect(() => normalizeLowSP1363(withS(new Uint8Array(32)))).toThrow(
      RemoteNativeIdentityCustodyError,
    );
    // zero-r
    const zeroR = new Uint8Array(64);
    zeroR.set(new Uint8Array(32).fill(1), 32);
    expect(() => normalizeLowSP1363(zeroR)).toThrow(/out of range/);
    // wrong length
    expect(() => normalizeLowSP1363(new Uint8Array(63))).toThrow(/64 bytes/);
  });
});

// ---------------------------------------------------------------------------
// Criterion 13: the fake signs the fixture message; the signature, assembled
// into a full 239-byte proof, round-trips through decodePossessionProof and
// verifies against the fake's public key.
// ---------------------------------------------------------------------------

describe("remote_identity_custody_codec_round_trip", () => {
  it("signs the fixture message and round-trips a full possession proof", async () => {
    const purpose = FIXTURE.purpose as PossessionPurposeV1;
    const unsigned = fromHex(FIXTURE.unsignedProof);
    const message = fromHex(FIXTURE.message);

    // The signing message is exactly domain || unsigned.
    expect(hex(possessionProofSigningMessage(unsigned, purpose))).toBe(hex(message));

    const module = new FakeRemoteIdentityCustodyModule();
    const gen = await module.generateP256(handle(0x4d), "ios-secure-enclave", false);
    const signature = await module.signP256(gen.handleId, message);
    expect(signature.length).toBe(64);

    // Assemble the full 239-byte proof: unsigned (175) || signature (64).
    const proof = new Uint8Array(unsigned.length + signature.length);
    proof.set(unsigned);
    proof.set(signature, unsigned.length);
    expect(proof.length).toBe(239);

    // decodePossessionProof runs the production low-S/structure validation.
    const decoded = decodePossessionProof(proof);
    expect(decoded.purpose).toBe(purpose);
    expect(hex(decoded.signatureP1363)).toBe(hex(signature));
    // Full encode/decode round-trip reproduces the assembled proof bytes.
    expect(hex(encodePossessionProof(decoded))).toBe(hex(proof));

    // The signature verifies against the fake's real public key.
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      {
        kty: "EC",
        crv: "P-256",
        x: bytesToBase64Url(gen.publicKey.x),
        y: bytesToBase64Url(gen.publicKey.y),
      },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      new Uint8Array(signature),
      message,
    );
    expect(ok).toBe(true);
  });
});

function withS(s: Uint8Array): Uint8Array {
  const sig = new Uint8Array(64);
  sig.set(new Uint8Array(32).fill(1), 0); // nonzero r
  sig.set(s, 32);
  return sig;
}

function fromHex(value: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
