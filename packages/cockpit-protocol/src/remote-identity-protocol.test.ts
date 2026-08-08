import { describe, expect, it } from "vitest";
import vectors from "../fixtures/remote-identity-protocol-v1.json";
import {
  decodeCustodyEvidence,
  decodeEnrollmentConfirmation,
  decodeEnrollmentTranscript,
  decodePossessionContext,
  decodePossessionProof,
  decodeRemoteIdentityProposal,
  encodeCustodyEvidence,
  encodeEnrollmentConfirmation,
  encodeEnrollmentTranscript,
  encodePossessionContext,
  encodePossessionProof,
  encodeRemoteIdentityProposal,
  PossessionPurpose,
  parseRemoteIdentityCertificateJws,
  possessionChallengeDomain,
  possessionSignatureDomain,
  remoteIdentitySha256,
  remoteIdentitySha256Sync,
} from "./remote-identity-protocol";

const fromHex = (value: string) =>
  Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
function reconstruct(codec: string, bytes: Uint8Array): Uint8Array {
  switch (codec) {
    case "FCIP":
      return encodeRemoteIdentityProposal(decodeRemoteIdentityProposal(bytes));
    case "FCEN":
      return encodeEnrollmentTranscript(decodeEnrollmentTranscript(bytes));
    case "FCCE":
      return encodeCustodyEvidence(decodeCustodyEvidence(bytes));
    case "FCPC":
      return encodePossessionContext(decodePossessionContext(bytes));
    case "FCPP":
      return encodePossessionProof(decodePossessionProof(bytes));
    case "FCCF":
      return encodeEnrollmentConfirmation(decodeEnrollmentConfirmation(bytes));
    case "JWS":
      parseRemoteIdentityCertificateJws(new TextDecoder().decode(bytes));
      return bytes;
    default:
      throw new Error("unknown fixture codec");
  }
}

describe("remote_identity_protocol_cross_language_vectors", () => {
  it("reconstructs and rejects the shared byte corpus", () => {
    expect(vectors.valid.length).toBeGreaterThan(0);
    expect(vectors.malformed.length).toBeGreaterThan(0);
    for (const vector of vectors.valid) {
      const bytes = fromHex(vector.hex);
      expect(bytes.length).toBeGreaterThan(0);
      expect(reconstruct(vector.codec, bytes)).toEqual(bytes);
    }
    for (const vector of vectors.malformed) {
      expect(() => reconstruct(vector.codec, fromHex(vector.hex))).toThrow();
    }
  });
  it("exhausts purpose domains", () => {
    for (const purpose of Object.values(PossessionPurpose)) {
      expect(possessionChallengeDomain(purpose).at(-1)).toBe(0);
      expect(possessionSignatureDomain(purpose).at(-1)).toBe(0);
    }
  });
  it("matches the SHA-256 known-answer vector", async () => {
    const input = new TextEncoder().encode("abc"),
      expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    expect(
      Array.from(remoteIdentitySha256Sync(input), (x) => x.toString(16).padStart(2, "0")).join(""),
    ).toBe(expected);
    expect(await remoteIdentitySha256(input)).toEqual(remoteIdentitySha256Sync(input));
  });
});
