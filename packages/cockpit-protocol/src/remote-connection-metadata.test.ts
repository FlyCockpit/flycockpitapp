import { describe, expect, it } from "vitest";
import fixture from "../fixtures/remote/connection-metadata-v1.json";
import {
  isAllowedMetadataRowField,
  isForbiddenMetadataField,
  REMOTE_METADATA_PSEUDONYM_DOMAINS,
  RemoteMetadataError,
  remoteMetadataBytesBucket,
  remoteMetadataCellTuple,
  remoteMetadataCorrectionClosesAt,
  remoteMetadataDecodePseudonymMessage,
  remoteMetadataDurationBucket,
  remoteMetadataPseudonymFromDigest,
  remoteMetadataPseudonymMessage,
  remoteMetadataPseudonymToHex,
  remoteMetadataTimeBucket,
  validateMetadataRetentionDays,
} from "./remote-connection-metadata";

const hex = (value: Uint8Array) =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
// Reject malformed hex: `/../g` silently DROPS an odd trailing nibble (so a
// `messageHex` corrupted from `...00` to `...000` would round-trip to the
// original bytes), and non-hex chars parse to NaN. Fail closed instead.
const bytes = (text: string) => {
  if (text.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(text)) {
    throw new Error(`invalid hex string: ${text}`);
  }
  return Uint8Array.from(text.match(/../g) ?? [], (v) => Number.parseInt(v, 16));
};
const captureError = (fn: () => void): RemoteMetadataError => {
  try {
    fn();
  } catch (e) {
    if (e instanceof RemoteMetadataError) return e;
    throw e;
  }
  throw new Error("expected a RemoteMetadataError to be thrown");
};

describe("remote connection metadata v1 fixtures and buckets", () => {
  it("remote_metadata_bucket_boundary_vectors: time bucket, duration, bytes", () => {
    expect(fixture.timeBucket.examples.length).toBeGreaterThan(0);
    for (const ex of fixture.timeBucket.examples) {
      expect(remoteMetadataTimeBucket(ex.epochSeconds)).toBe(ex.timeBucket);
    }
    expect(remoteMetadataTimeBucket(0)).toBe(0);
    expect(remoteMetadataTimeBucket(3600)).toBe(3600);
    expect(remoteMetadataTimeBucket(3601)).toBe(3600);

    for (const v of fixture.durationBuckets) {
      expect(remoteMetadataDurationBucket(v.seconds)).toBe(v.bucket);
    }
    expect(remoteMetadataDurationBucket(0)).toBe(1);
    expect(remoteMetadataDurationBucket(4)).toBe(1);
    expect(remoteMetadataDurationBucket(5)).toBe(2);
    expect(remoteMetadataDurationBucket(3600)).toBe(6);

    for (const v of fixture.bytesBuckets) {
      expect(remoteMetadataBytesBucket(v.bytes)).toBe(v.bucket);
    }
    expect(remoteMetadataBytesBucket(0)).toBe(0);
    expect(remoteMetadataBytesBucket(1)).toBe(1);
    expect(remoteMetadataBytesBucket(65535)).toBe(1);
    expect(remoteMetadataBytesBucket(65536)).toBe(2);
    expect(remoteMetadataBytesBucket(1073741824)).toBe(6);
  });

  it("remote_metadata_classification_guard: allowed fields and forbidden corpus", () => {
    expect(fixture.allowedRowFields.length).toBeGreaterThan(0);
    for (const field of fixture.allowedRowFields) {
      expect(isAllowedMetadataRowField(field)).toBe(true);
    }
    expect(isAllowedMetadataRowField("rawIp")).toBe(false);
    expect(isAllowedMetadataRowField("content")).toBe(false);

    expect(fixture.forbiddenFields.length).toBeGreaterThan(0);
    expect(isForbiddenMetadataField("rawIp")).toBe(true);
    expect(isForbiddenMetadataField("sdp")).toBe(true);
    expect(isForbiddenMetadataField("turnPassword")).toBe(true);
    expect(isForbiddenMetadataField("content")).toBe(true);
    expect(isForbiddenMetadataField("tenantPseudonym")).toBe(false);
  });

  it("remote_ledger_pseudonym_vectors: five literal domains and framing", () => {
    expect(fixture.pseudonymSchemas.length).toBe(5);
    for (const schema of fixture.pseudonymSchemas) {
      expect(schema.domain).toBeTruthy();
      expect(schema.components.length).toBe(1);
    }
    const alias = bytes("0102030405060708090a0b0c0d0e0f10");
    const msg = remoteMetadataPseudonymMessage(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant, [
      { kind: 1, bytes: alias },
    ]);
    expect(hex(msg)).toBe(fixture.positiveVectors[0]!.messageHex);
  });

  it("rejects wrong domain/type pairing, zero/multiple components, unknown domain", () => {
    expect(() =>
      remoteMetadataPseudonymMessage(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant, [
        { kind: 2, bytes: bytes("0102030405060708090a0b0c0d0e0f10") },
      ]),
    ).toThrow(RemoteMetadataError);
    expect(() =>
      remoteMetadataPseudonymMessage("flycockpit.remote.metadata.unknown.v1", [
        { kind: 1, bytes: bytes("0102030405060708090a0b0c0d0e0f10") },
      ]),
    ).toThrow(RemoteMetadataError);
    expect(() =>
      remoteMetadataPseudonymMessage(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant, []),
    ).toThrow(RemoteMetadataError);
    expect(() =>
      remoteMetadataPseudonymMessage(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant, [
        { kind: 1, bytes: new Uint8Array(16) },
      ]),
    ).toThrow(RemoteMetadataError);
  });

  it("malformed vectors: every fixture vector is rejected by decode and construction", () => {
    const validClasses = [
      "unknown_domain",
      "zero_components",
      "multiple_components",
      "domain_component_mismatch",
      "trailing_byte",
    ];
    for (const vector of fixture.malformedVectors) {
      // No default-skip arm: an unknown rejection string fails the test.
      expect(validClasses).toContain(vector.rejection);

      let decodeErr: unknown;
      try {
        remoteMetadataDecodePseudonymMessage(bytes(vector.messageHex));
      } catch (e) {
        decodeErr = e;
      }
      expect(decodeErr).toBeInstanceOf(RemoteMetadataError);
      expect((decodeErr as RemoteMetadataError).code).toBe(vector.rejection);

      // Null-construction contract (matches Rust): `trailing_byte` is the only
      // class no builder can emit, so it MUST carry `construction: null`; every
      // other class MUST carry a non-null construction the builder also rejects.
      // A future `zero_components`/`multiple_components` set to null fails here.
      if (vector.rejection === "trailing_byte") {
        expect(vector.construction).toBeNull();
      } else {
        expect(vector.construction).not.toBeNull();
      }

      if (vector.construction) {
        const components: { kind: number; bytes: Uint8Array }[] = [];
        for (const c of vector.construction.components) {
          components.push({ kind: c.kind, bytes: bytes(c.aliasHex) });
        }
        let ctorErr: unknown;
        try {
          remoteMetadataPseudonymMessage(vector.construction.domain, components);
        } catch (e) {
          ctorErr = e;
        }
        expect(ctorErr).toBeInstanceOf(RemoteMetadataError);
        expect((ctorErr as RemoteMetadataError).code).toBe(vector.rejection);
      }
    }
    // The corpus is fixed at exactly five vectors with an exact name→rejection
    // mapping. Asserting only the SET of classes would miss a 6th duplicate-
    // class vector (caught by the length check) and a renamed vector (caught by
    // the pair list) — so both cardinality and names are pinned.
    expect(fixture.malformedVectors.length).toBe(5);
    const actualPairs = fixture.malformedVectors.map((v) => `${v.name}:${v.rejection}`).sort();
    const expectedPairs = [
      "wrong_domain_type_pairing:domain_component_mismatch",
      "zero_components:zero_components",
      "multiple_components:multiple_components",
      "unknown_domain:unknown_domain",
      "trailing_byte:trailing_byte",
    ].sort();
    expect(actualPairs).toEqual(expectedPairs);
  });

  it("positive vectors: decode round-trips construction", () => {
    for (const vector of fixture.positiveVectors) {
      const message = bytes(vector.messageHex);
      const decoded = remoteMetadataDecodePseudonymMessage(message);
      expect(decoded.domain).toBe(vector.domain);
      expect(decoded.components.length).toBe(1);
      expect(decoded.components[0]!.kind).toBe(vector.componentKind);
      expect(hex(decoded.components[0]!.bytes)).toBe(vector.aliasHex);
      const reencoded = remoteMetadataPseudonymMessage(decoded.domain, decoded.components);
      expect(hex(reencoded)).toBe(vector.messageHex);
    }
  });

  it("decode: leading 0x00 is unknown_domain, absent separator is truncated", () => {
    // Cross-language regression: Rust maps a leading 0x00 (empty domain) to
    // UnknownDomain; TS must agree, and must not conflate it with truncation.
    let emptyDomainErr: unknown;
    try {
      remoteMetadataDecodePseudonymMessage(Uint8Array.of(0x00));
    } catch (e) {
      emptyDomainErr = e;
    }
    expect(emptyDomainErr).toBeInstanceOf(RemoteMetadataError);
    expect((emptyDomainErr as RemoteMetadataError).code).toBe("unknown_domain");

    // No 0x00 separator at all is a genuine truncation.
    let noSepErr: unknown;
    try {
      remoteMetadataDecodePseudonymMessage(Uint8Array.of(0x66, 0x67));
    } catch (e) {
      noSepErr = e;
    }
    expect(noSepErr).toBeInstanceOf(RemoteMetadataError);
    expect((noSepErr as RemoteMetadataError).code).toBe("truncated");
  });

  it("decode/construct: a prototype property name domain is unknown_domain", () => {
    // "toString" is inherited on plain objects; own-property lookup must reject
    // it as unknown_domain (parity with Rust), not domain_component_mismatch.
    const alias = bytes("0102030405060708090a0b0c0d0e0f10");
    let ctorErr: unknown;
    try {
      remoteMetadataPseudonymMessage("toString", [{ kind: 1, bytes: alias }]);
    } catch (e) {
      ctorErr = e;
    }
    expect(ctorErr).toBeInstanceOf(RemoteMetadataError);
    expect((ctorErr as RemoteMetadataError).code).toBe("unknown_domain");

    // "toString" | 0x00 | count 1 | kind 1 | len 16 | alias.
    const payload = bytes("746f537472696e6700010100100102030405060708090a0b0c0d0e0f10");
    let decErr: unknown;
    try {
      remoteMetadataDecodePseudonymMessage(payload);
    } catch (e) {
      decErr = e;
    }
    expect(decErr).toBeInstanceOf(RemoteMetadataError);
    expect((decErr as RemoteMetadataError).code).toBe("unknown_domain");
  });

  it("construction errors preserve descriptive messages alongside wire codes", () => {
    // Pre-existing rejections must keep their original human-readable messages
    // (callers may branch on/report `.message`) while carrying the wire `.code`.
    const tenant = REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant;
    const alias = bytes("0102030405060708090a0b0c0d0e0f10");

    const unknown = captureError(() =>
      remoteMetadataPseudonymMessage("nope.v1", [{ kind: 1, bytes: alias }]),
    );
    expect(unknown.code).toBe("unknown_domain");
    expect(unknown.message).toBe("unknown pseudonym domain");

    const zero = captureError(() => remoteMetadataPseudonymMessage(tenant, []));
    expect(zero.code).toBe("zero_components");
    expect(zero.message).toBe("exactly one component required");

    const multiple = captureError(() =>
      remoteMetadataPseudonymMessage(tenant, [
        { kind: 1, bytes: alias },
        { kind: 1, bytes: alias },
      ]),
    );
    expect(multiple.code).toBe("multiple_components");
    expect(multiple.message).toBe("exactly one component required");

    const mismatch = captureError(() =>
      remoteMetadataPseudonymMessage(tenant, [{ kind: 2, bytes: alias }]),
    );
    expect(mismatch.code).toBe("domain_component_mismatch");
    expect(mismatch.message).toBe("domain-component kind mismatch");

    const badBytes = captureError(() =>
      remoteMetadataPseudonymMessage(tenant, [{ kind: 1, bytes: new Uint8Array(16) }]),
    );
    expect(badBytes.code).toBe("invalid_component_bytes");
    expect(badBytes.message).toBe("component bytes must be nonzero 16 bytes");
  });

  it("construction fails closed on malformed component shapes", () => {
    // A sparse/undefined/null/wrong-typed component must fail closed with a
    // stable `invalid_component_bytes` code — never a raw TypeError.
    type Components = Parameters<typeof remoteMetadataPseudonymMessage>[1];
    const domain = REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant;
    const malformed = [
      [undefined],
      [null],
      [{ kind: 1, bytes: [1, 2, 3] }],
    ] as unknown as Components[];
    for (const bad of malformed) {
      const err = captureError(() => remoteMetadataPseudonymMessage(domain, bad));
      expect(err.code).toBe("invalid_component_bytes");
    }
  });

  it("construction fails closed on a null/undefined/non-array container", () => {
    // The container itself (not just its elements) must be validated before
    // `.length` — a null/undefined/non-array yields a stable code, not a raw
    // TypeError.
    type Components = Parameters<typeof remoteMetadataPseudonymMessage>[1];
    const domain = REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant;
    const containers = [null, undefined, "not-an-array", 42] as unknown as Components[];
    for (const bad of containers) {
      const err = captureError(() => remoteMetadataPseudonymMessage(domain, bad));
      expect(err.code).toBe("invalid_component_bytes");
    }
  });

  it("decode fails closed on a null/undefined/non-Uint8Array input", () => {
    // The decode boundary must validate its input before `.indexOf`, mirroring
    // the construct boundary — a stable code, never a raw TypeError.
    type Bytes = Parameters<typeof remoteMetadataDecodePseudonymMessage>[0];
    const inputs = [null, undefined, "nope", [1, 2, 3]] as unknown as Bytes[];
    for (const bad of inputs) {
      const err = captureError(() => remoteMetadataDecodePseudonymMessage(bad));
      expect(err.code).toBe("invalid_component_bytes");
    }
  });

  it("pseudonym from digest and hex encoding", () => {
    const digest = new Uint8Array(32).fill(0xab);
    const p = remoteMetadataPseudonymFromDigest(digest);
    expect(p.length).toBe(16);
    expect(remoteMetadataPseudonymToHex(p)).toBe("ab".repeat(16));
    expect(() => remoteMetadataPseudonymFromDigest(new Uint8Array(16))).toThrow(
      RemoteMetadataError,
    );
  });

  it("retention bounds: 0, 1, 30, 365, invalid", () => {
    expect(validateMetadataRetentionDays(0)).toBe(0);
    expect(validateMetadataRetentionDays(1)).toBe(1);
    expect(validateMetadataRetentionDays(30)).toBe(30);
    expect(validateMetadataRetentionDays(365)).toBe(365);
    expect(() => validateMetadataRetentionDays(-1)).toThrow(RemoteMetadataError);
    expect(() => validateMetadataRetentionDays(366)).toThrow(RemoteMetadataError);
    expect(() => validateMetadataRetentionDays(30.5)).toThrow(RemoteMetadataError);
  });

  it("cell tuple is canonical 7-discriminant fixed-width", () => {
    const tuple = remoteMetadataCellTuple({
      serviceTier: 1,
      region: 2,
      routeClass: 1,
      outcome: 1,
      ingressBytesBucket: 1,
      egressBytesBucket: 2,
      durationBucket: 3,
    });
    expect(tuple.length).toBe(7);
    expect(Array.from(tuple)).toEqual([1, 2, 1, 1, 1, 2, 3]);
  });

  it("aggregate correction horizon is 8 days (day + 7 after close)", () => {
    const utcDay = 19_937;
    expect(remoteMetadataCorrectionClosesAt(utcDay)).toBe(utcDay + 8 * 86_400);
  });

  it("fixture has at least one positive and one malformed vector", () => {
    expect(fixture.positiveVectors.length).toBeGreaterThanOrEqual(1);
    expect(fixture.malformedVectors.length).toBeGreaterThanOrEqual(1);
  });

  it("enum discriminants match fixture byte-for-byte", () => {
    expect(fixture.enums.serviceTier.public_saas).toBe(1);
    expect(fixture.enums.serviceTier.enterprise).toBe(2);
    expect(fixture.enums.transport.webrtc).toBe(1);
    expect(fixture.enums.routeClass.direct).toBe(1);
    expect(fixture.enums.outcome.connected).toBe(1);
    expect(fixture.enums.reason.none).toBe(0);
    expect(fixture.enums.custodyClass.origin_protected).toBe(1);
    expect(fixture.enums.region.unknown).toBe(0);
    expect(fixture.enums.durationBucket.lt_5s).toBe(1);
    expect(fixture.enums.bytesBucket.zero).toBe(0);
  });
});
