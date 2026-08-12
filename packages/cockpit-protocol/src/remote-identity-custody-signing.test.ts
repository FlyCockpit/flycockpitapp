import { describe, expect, it } from "vitest";
import fixture from "../fixtures/remote-identity-custody-signing-v1.json";
import {
  decodePossessionProof,
  encodePossessionProof,
  PossessionPurpose,
  type PossessionPurposeV1,
  possessionProofSigningDigest,
  possessionProofSigningMessage,
  possessionSignatureDomain,
  remoteIdentitySha256,
} from "./remote-identity-protocol";

const fromHex = (value: string) =>
  Uint8Array.from(value.match(/../g) ?? [], (b) => Number.parseInt(b, 16));
const arr = (b: Uint8Array) => Array.from(b);

describe("remote_identity_custody_signing_fixture", () => {
  const purpose = fixture.purpose as PossessionPurposeV1;
  const unsigned = fromHex(fixture.unsignedProof);
  const domain = fromHex(fixture.domain);
  const message = fromHex(fixture.message);
  const digest = fromHex(fixture.digest);
  const lowS = fromHex(fixture.signatureLowS);
  const highS = fromHex(fixture.signatureHighS);

  it("fixture_purpose_is_attempt_daemon", () => {
    expect(fixture.purpose).toBe(PossessionPurpose.attempt_daemon);
    expect(unsigned.length).toBe(175);
    expect(message.length).toBe(domain.length + unsigned.length);
  });

  it("digest_equals_sha256_of_message", async () => {
    // Independent recomputation via the production SHA-256 entry point.
    const actual = await remoteIdentitySha256(message);
    expect(arr(actual)).toEqual(arr(digest));
  });

  it("possession_proof_signing_message_matches_fixture", () => {
    const msg = possessionProofSigningMessage(unsigned, purpose);
    expect(arr(msg)).toEqual(arr(message));
    // message = domain || unsigned, and domain is the production signature domain.
    expect(arr(msg.slice(0, domain.length))).toEqual(arr(domain));
    expect(arr(msg.slice(domain.length))).toEqual(arr(unsigned));
    expect(arr(possessionSignatureDomain(purpose))).toEqual(arr(domain));
  });

  it("possession_proof_signing_digest_matches_fixture", async () => {
    const d = await possessionProofSigningDigest(unsigned, purpose);
    expect(arr(d)).toEqual(arr(digest));
  });

  it("webcrypto_verifies_pinned_low_s_signature_over_message", async () => {
    const raw = new Uint8Array(65);
    raw[0] = 0x04;
    raw.set(fromHex(fixture.publicKey.x), 1);
    raw.set(fromHex(fixture.publicKey.y), 33);
    const key = await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    // WebCrypto hashes internally, so it verifies the low-S signature over the
    // MESSAGE — proving the message-based signing contract end to end.
    const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, lowS, message);
    expect(ok).toBe(true);
    // The high-S companion also verifies (both s and n-s verify in ECDSA), which
    // is exactly why provider-side low-S normalization is required.
    const okHigh = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      highS,
      message,
    );
    expect(okHigh).toBe(true);
  });

  it("production_codec_accepts_the_signed_proof", () => {
    // Assemble the full 239-byte proof = unsigned(175) || low-S signature(64)
    // and route it through the PRODUCTION codec, whose validateLowSP1363 gate
    // rejects zero/high-S signatures.
    const proofBytes = new Uint8Array(239);
    proofBytes.set(unsigned);
    proofBytes.set(lowS, 175);
    const decoded = decodePossessionProof(proofBytes);
    expect(decoded.purpose).toBe(purpose);
    // Re-encoding through the production entry point round-trips byte-identically.
    expect(arr(encodePossessionProof(decoded))).toEqual(arr(proofBytes));
  });

  it("production_codec_rejects_the_high_s_form", () => {
    const proofBytes = new Uint8Array(239);
    proofBytes.set(unsigned);
    proofBytes.set(highS, 175);
    expect(() => decodePossessionProof(proofBytes)).toThrow();
  });
});
