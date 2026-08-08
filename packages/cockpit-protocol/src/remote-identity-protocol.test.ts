import { describe, expect, it } from "vitest";
import vectors from "../fixtures/remote-identity-protocol-v1.json";
import {
  decodePossessionContext,
  encodePossessionContext,
  PossessionPurpose,
  possessionChallengeDomain,
  possessionSignatureDomain,
} from "./remote-identity-protocol";

describe("remote_identity_protocol_cross_language_vectors", () => {
  it("has nonempty shared coverage and exact purpose contexts", () => {
    expect(vectors.valid.magics.length).toBe(6);
    expect(vectors.valid.purposes.length).toBe(7);
    expect(vectors.valid.roles.length).toBe(3);
    expect(vectors.malformed.length).toBeGreaterThan(0);
    const digest = new Uint8Array(32).fill(7);
    for (const purpose of Object.values(PossessionPurpose)) {
      const context =
        purpose === 1
          ? { purpose, proposedIdentityDigest: digest, enrollmentTranscriptDigest: digest }
          : purpose <= 4
            ? { purpose, currentCertificateDigest: digest, proposedIdentityDigest: digest }
            : purpose <= 6
              ? { purpose, currentCertificateDigest: digest, attemptRequestDigest: digest }
              : { purpose, currentCertificateDigest: digest, revocationRequestDigest: digest };
      const bytes = encodePossessionContext(context);
      expect(encodePossessionContext(decodePossessionContext(bytes))).toEqual(bytes);
      expect(possessionChallengeDomain(purpose).at(-1)).toBe(0);
      expect(possessionSignatureDomain(purpose).at(-1)).toBe(0);
    }
  });
});
