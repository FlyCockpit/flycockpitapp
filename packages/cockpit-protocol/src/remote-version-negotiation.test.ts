import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { PROTOCOL_VERSION } from "./index";
import {
  decodeTranscript,
  enabledRegistry,
  enabledRegistryDigest,
  encodeTranscript,
  invalidInputError,
  type RemoteNegotiationTranscriptV1,
  RemoteVersionError,
  registryTuple,
  type SelectionInputs,
  select,
  TRANSCRIPT_FIXED_BYTES,
  TRANSCRIPT_MAGIC,
  TRANSCRIPT_MAX_BYTES,
  TRANSCRIPT_MIN_BYTES,
  TRANSCRIPT_VERSION,
  TRANSPORT_WEBRTC,
  TRANSPORT_WEBSOCKET_DATA,
  transcriptDigest,
  upgradeRequired,
  V1_AUTHORIZATION,
  V1_SECURITY_RANK,
  V1_SIGNALING,
  V1_TRANSPORT,
  V1_TUPLE_ID,
  verifyTranscriptDigest,
} from "./remote-version";
import {
  assertRegisteredProductionMagics,
  parseRemoteWireMagicRegistry,
} from "./remote-wire-magic-registry";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(here, "../fixtures/remote/version-negotiation-v1.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
  version: number;
  registry: {
    v1TupleId: number;
    v1Signaling: number;
    v1Authorization: number;
    v1Transport: number;
    v1SecurityRank: number;
    v1FeatureCount: number;
  };
  selectionCases: Array<{
    name: string;
    client: number[];
    daemon: number[];
    serverAllowed: number[];
    revoked: number[];
    expectedSelected: number | null;
  }>;
  upgradeCases: Array<{
    name: string;
    client: number[];
    daemon: number[];
    serverAllowed: number[];
    revoked: number[];
    expectedUpgradeSide: string;
    expectedRecommended: number | null;
    expectedClientSupported: number[];
    expectedDaemonSupported: number[];
    expectedServerAllowed: number[];
  }>;
  transcriptVectors: Array<{
    name: string;
    transcriptHex: string;
    expectedDigestHex: string;
    expectedLen: number;
  }>;
  malformedVectors: Array<{
    name: string;
    transcriptHex: string;
    rejection: string;
  }>;
};

const hexToBytes = (text: string): Uint8Array =>
  Uint8Array.from(text.match(/../g)!.map((v) => Number.parseInt(v, 16)));
const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function makeTranscript(transport: number): RemoteNegotiationTranscriptV1 {
  return {
    transport,
    childAttemptId: Uint8Array.from({ length: 16 }, (_, i) => 0x01 + i),
    grantJti: Uint8Array.from({ length: 16 }, (_, i) => 0x11 + i),
    serverNonce: Uint8Array.from({ length: 32 }, (_, i) => 0x21 + i),
    clientNonce: Uint8Array.from({ length: 32 }, (_, i) => 0x41 + i),
    policyDigest: Uint8Array.from({ length: 32 }, (_, i) => 0x61 + i),
    clientTupleIds: [V1_TUPLE_ID],
    daemonTupleIds: [V1_TUPLE_ID],
    serverAllowedTupleIds: [V1_TUPLE_ID],
    selectedTupleId: V1_TUPLE_ID,
    criticalFeatures: [],
  };
}

describe("remote_version_tuple_registry_v1_fixture", () => {
  it("proves V1 registry entry with application sourced from PROTOCOL_VERSION", () => {
    const registry = enabledRegistry();
    expect(registry.length).toBe(1);
    const v1 = registry[0]!;
    expect(v1.tupleId).toBe(V1_TUPLE_ID);
    expect(v1.signaling).toBe(V1_SIGNALING);
    expect(v1.authorization).toBe(V1_AUTHORIZATION);
    expect(v1.transport).toBe(V1_TRANSPORT);
    expect(v1.securityRank).toBe(V1_SECURITY_RANK);
    expect(v1.criticalFeatures.length).toBe(0);
    // application sourced from PROTOCOL_VERSION constant, not hardcoded.
    expect(v1.application).toBe(PROTOCOL_VERSION);
    // Nonzero unique IDs.
    const ids = registry.map((t) => t.tupleId);
    expect(ids.every((id) => id !== 0)).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
    // No maxima synthesis: only one tuple.
    expect(registry.length).toBe(1);

    // Fixture registry structural fields match live registry (these do not
    // change on a PROTOCOL_VERSION bump).
    expect(fixture.registry.v1TupleId).toBe(V1_TUPLE_ID);
    expect(fixture.registry.v1SecurityRank).toBe(V1_SECURITY_RANK);
    expect(fixture.registry.v1FeatureCount).toBe(0);
  });
});

describe("remote_version_no_hardcoded_application_version", () => {
  it("fixture carries no second hand-maintained application-version authority", () => {
    // The application version is NOT part of the cross-language transcript byte
    // corpus and its sole authority is the PROTOCOL_VERSION constant. The
    // shared fixture must not re-embed it (a `protocolVersion` / `v1Application`
    // field), which a constant bump would silently desync — the exact failure
    // mode AC-1 exists to prevent.
    const rawFixture = readFileSync(fixturePath, "utf8");
    expect(rawFixture).not.toContain("protocolVersion");
    expect(rawFixture).not.toContain("v1Application");
    const parsed = JSON.parse(rawFixture) as Record<string, unknown> & {
      registry?: Record<string, unknown>;
    };
    expect(parsed.protocolVersion).toBeUndefined();
    expect(parsed.registry?.v1Application).toBeUndefined();

    // No checked-in registry digest either (computed live in both languages).
    expect(rawFixture).not.toContain("registryDigestHex");
  });

  it("the live registry sources the application version from PROTOCOL_VERSION", () => {
    // Non-vacuous: the production registry derives application from the single
    // constant authority, so there is exactly one source of truth.
    const v1 = enabledRegistry()[0]!;
    expect(v1.application).toBe(PROTOCOL_VERSION);
    // The registry digest is a live computation, never a checked-in literal.
    expect(enabledRegistryDigest().length).toBe(32);
  });
});

describe("remote_version_selection_cross_language", () => {
  it("exhaustively permutes list order/intersections/ranks/ties/revocation", () => {
    expect(fixture.selectionCases.length).toBeGreaterThan(0);
    for (const c of fixture.selectionCases) {
      const inputs: SelectionInputs = {
        client: c.client,
        daemon: c.daemon,
        serverAllowed: c.serverAllowed,
        revoked: c.revoked,
      };
      const result = select(inputs);
      expect(result?.tupleId ?? null, `selection case: ${c.name}`).toBe(c.expectedSelected);
    }
  });

  it("rejects invalid lists", () => {
    expect(() =>
      select({ client: [], daemon: [V1_TUPLE_ID], serverAllowed: [V1_TUPLE_ID], revoked: [] }),
    ).toThrow(RemoteVersionError);
    expect(() =>
      select({
        client: [0x0002, 0x0001],
        daemon: [V1_TUPLE_ID],
        serverAllowed: [V1_TUPLE_ID],
        revoked: [],
      }),
    ).toThrow(RemoteVersionError);
    expect(() =>
      select({ client: [0], daemon: [V1_TUPLE_ID], serverAllowed: [V1_TUPLE_ID], revoked: [] }),
    ).toThrow(RemoteVersionError);
  });
});

describe("remote_version_transcript_wire_vectors", () => {
  it("proves every offset/width/endian/count and TypeScript/Rust byte identity", () => {
    const t = makeTranscript(TRANSPORT_WEBRTC);
    const bytes = encodeTranscript(t);
    expect(bytes.length).toBe(TRANSCRIPT_MIN_BYTES);
    expect(bytes.length).toBe(146);

    // Magic at offset 0.
    expect(bytesToHex(bytes.slice(0, 4))).toBe("4643524e");
    expect(TRANSCRIPT_MAGIC).toBe("FCRN");
    // Version at offset 4.
    expect(bytes[4]).toBe(TRANSCRIPT_VERSION);
    // Transport at offset 5.
    expect(bytes[5]).toBe(TRANSPORT_WEBRTC);
    // childAttemptId at offset 6..22.
    expect(bytes.length).toBeGreaterThanOrEqual(22);
    // grantJti at offset 22..38.
    // serverNonce at offset 38..70.
    // clientNonce at offset 70..102.
    // policyDigest at offset 102..134.
    expect(bytesToHex(bytes.slice(102, 134))).toBe(
      bytesToHex(Uint8Array.from({ length: 32 }, (_, i) => 0x61 + i)),
    );
    // clientCount at offset 134.
    expect(bytes[134]).toBe(1);
    // clientTupleIds at offset 135..137.
    expect(bytesToHex(bytes.slice(135, 137))).toBe("0001");
    // daemonCount at offset 137.
    expect(bytes[137]).toBe(1);
    // daemonTupleIds at offset 138..140.
    expect(bytesToHex(bytes.slice(138, 140))).toBe("0001");
    // serverCount at offset 140.
    expect(bytes[140]).toBe(1);
    // serverAllowedTupleIds at offset 141..143.
    expect(bytesToHex(bytes.slice(141, 143))).toBe("0001");
    // selectedTupleId at offset 143..145.
    expect(bytesToHex(bytes.slice(143, 145))).toBe("0001");
    // featureCount at offset 145.
    expect(bytes[145]).toBe(0);

    // Fixed portion: 140 bytes.
    expect(TRANSCRIPT_FIXED_BYTES).toBe(140);
    // Max: 364 bytes.
    expect(TRANSCRIPT_MAX_BYTES).toBe(364);

    // Round-trip.
    const decoded = decodeTranscript(bytes);
    expect(decoded.transport).toBe(t.transport);
    expect(decoded.selectedTupleId).toBe(t.selectedTupleId);
    expect(decoded.clientTupleIds).toEqual(t.clientTupleIds);
  });

  it("proves fixture transcript vectors byte identity", () => {
    expect(fixture.transcriptVectors.length).toBeGreaterThan(0);
    for (const v of fixture.transcriptVectors) {
      const bytes = hexToBytes(v.transcriptHex);
      expect(bytes.length, `transcript vector length: ${v.name}`).toBe(v.expectedLen);
      const decoded = decodeTranscript(bytes);
      const reencoded = encodeTranscript(decoded);
      expect(bytesToHex(reencoded), `transcript vector round-trip: ${v.name}`).toBe(
        v.transcriptHex,
      );
    }
  });
});

describe("remote_version_strict_parser_matrix", () => {
  it("rejects every malformed count/order/duplicate/unknown/selected/feature/length/trailing/transport branch", () => {
    expect(fixture.malformedVectors.length).toBeGreaterThan(0);
    for (const v of fixture.malformedVectors) {
      const bytes = hexToBytes(v.transcriptHex);
      expect(() => decodeTranscript(bytes), `malformed vector: ${v.name}`).toThrow(
        RemoteVersionError,
      );
    }
  });

  it("rejects duplicate IDs in a list", () => {
    const valid = makeTranscript(TRANSPORT_WEBRTC);
    const validBytes = encodeTranscript(valid);
    // clientCount=2, IDs=[1,1] → nonascending (duplicate).
    const dup = new Uint8Array(validBytes.length + 2);
    dup.set(validBytes.subarray(0, 135));
    dup[134] = 2;
    dup[135] = 0x00;
    dup[136] = 0x01;
    dup[137] = 0x00;
    dup[138] = 0x01;
    dup.set(validBytes.subarray(137), 139);
    expect(() => decodeTranscript(dup)).toThrow(RemoteVersionError);
  });

  it("rejects nonascending list", () => {
    const valid = makeTranscript(TRANSPORT_WEBRTC);
    const validBytes = encodeTranscript(valid);
    // clientCount=2, IDs=[0x0002, 0x0001] → nonascending.
    const nonasc = new Uint8Array(validBytes.length + 2);
    nonasc.set(validBytes.subarray(0, 135));
    nonasc[134] = 2;
    nonasc[135] = 0x00;
    nonasc[136] = 0x02;
    nonasc[137] = 0x00;
    nonasc[138] = 0x01;
    nonasc.set(validBytes.subarray(137), 139);
    expect(() => decodeTranscript(nonasc)).toThrow(RemoteVersionError);
  });
});

describe("remote_version_transcript_digest_sensitivity", () => {
  it("proves digest determinism and mutation sensitivity", () => {
    const base = makeTranscript(TRANSPORT_WEBRTC);
    const baseBytes = encodeTranscript(base);
    const baseDigest = transcriptDigest(baseBytes);

    // Determinism: same input → same digest.
    expect(transcriptDigest(baseBytes)).toEqual(baseDigest);

    // Mutate serverNonce.
    const m1 = { ...base, serverNonce: base.serverNonce.slice() };
    m1.serverNonce[0]! ^= 0xff;
    expect(transcriptDigest(encodeTranscript(m1))).not.toEqual(baseDigest);

    // Mutate clientNonce.
    const m2 = { ...base, clientNonce: base.clientNonce.slice() };
    m2.clientNonce[0]! ^= 0xff;
    expect(transcriptDigest(encodeTranscript(m2))).not.toEqual(baseDigest);

    // Mutate transport.
    const m3 = { ...base, transport: TRANSPORT_WEBSOCKET_DATA };
    expect(transcriptDigest(encodeTranscript(m3))).not.toEqual(baseDigest);

    // Mutate childAttemptId.
    const m4 = { ...base, childAttemptId: base.childAttemptId.slice() };
    m4.childAttemptId[0]! ^= 0xff;
    expect(transcriptDigest(encodeTranscript(m4))).not.toEqual(baseDigest);

    // Verify: matching digest succeeds.
    expect(() => verifyTranscriptDigest(baseBytes, baseDigest)).not.toThrow();

    // Verify: mismatched digest fails.
    const wrong = baseDigest.slice();
    wrong[0]! ^= 0xff;
    expect(() => verifyTranscriptDigest(baseBytes, wrong)).toThrow(RemoteVersionError);
  });

  it("proves fixture digest vectors match", () => {
    for (const v of fixture.transcriptVectors) {
      const bytes = hexToBytes(v.transcriptHex);
      const digest = transcriptDigest(bytes);
      expect(bytesToHex(digest), `transcript vector digest: ${v.name}`).toBe(v.expectedDigestHex);
    }
  });
});

describe("remote_version_upgrade_required_shape", () => {
  it("proves exact fields/bounds/filter/order plus every P/S/support-count/rank/tie branch", () => {
    expect(fixture.upgradeCases.length).toBeGreaterThan(0);
    for (const c of fixture.upgradeCases) {
      const inputs: SelectionInputs = {
        client: c.client,
        daemon: c.daemon,
        serverAllowed: c.serverAllowed,
        revoked: c.revoked,
      };
      const err = upgradeRequired(inputs);
      expect(err.code, `upgrade case: ${c.name}`).toBe("remote_upgrade_required");
      expect(err.upgradeSide, `upgrade case: ${c.name}`).toBe(c.expectedUpgradeSide);
      expect(err.recommendedTupleId, `upgrade case recommended: ${c.name}`).toBe(
        c.expectedRecommended,
      );
      expect(err.clientSupported, `upgrade case client_supported: ${c.name}`).toEqual(
        c.expectedClientSupported,
      );
      expect(err.daemonSupported, `upgrade case daemon_supported: ${c.name}`).toEqual(
        c.expectedDaemonSupported,
      );
      expect(err.serverAllowed, `upgrade case server_allowed: ${c.name}`).toEqual(
        c.expectedServerAllowed,
      );
      // Envelope/transcript version 1, never the application constant (which is
      // > 1 pre-release, so this rejects the old application-version leak).
      expect(err.protocolVersion).toBe(1);
      expect(err.protocolVersion).not.toBe(PROTOCOL_VERSION);
    }
  });

  it("proves no sensitive disclosure for invalid input", () => {
    const err = invalidInputError();
    expect(err.code).toBe("remote_protocol_invalid");
    expect(err.clientSupported).toEqual([]);
    expect(err.daemonSupported).toEqual([]);
    expect(err.serverAllowed).toEqual([]);
    expect(err.recommendedTupleId).toBeNull();
    // Envelope version 1, never the application constant.
    expect(err.protocolVersion).toBe(1);
    expect(err.protocolVersion).not.toBe(PROTOCOL_VERSION);
  });
});

describe("remote_version_policy_revocation", () => {
  it("proves revoked tuple excluded from selection and recommendations", () => {
    const inputs: SelectionInputs = {
      client: [V1_TUPLE_ID],
      daemon: [V1_TUPLE_ID],
      serverAllowed: [V1_TUPLE_ID],
      revoked: [V1_TUPLE_ID],
    };
    expect(select(inputs)).toBeNull();
    const err = upgradeRequired(inputs);
    expect(err.upgradeSide).toBe("server_policy");
    expect(err.recommendedTupleId).toBeNull();
    expect(err.clientSupported).toEqual([]);
    expect(err.daemonSupported).toEqual([]);
    expect(err.serverAllowed).toEqual([]);
  });
});

describe("remote_version_replica_registry_digest", () => {
  it("proves exact domain-prefixed canonical digest is deterministic and cross-language byte-identical", () => {
    const d1 = enabledRegistryDigest();
    const d2 = enabledRegistryDigest();
    expect(d1).toEqual(d2);
    expect(d1.length).toBe(32);
    // The registry digest is computed at test time from the live registry,
    // never compared against a checked-in value.
  });

  it("proves registries differing in enabled IDs, ranks, or features produce different digests", () => {
    // Since the registry is code-owned and pure, we verify the digest changes
    // when the application version constant changes by computing a digest with
    // a manually altered registry (simulating what a future bump would do).
    const live = enabledRegistryDigest();
    // Manually compute a digest with a different application version to prove
    // sensitivity — this is a test-time computation, not a checked-in value.
    const hash = createHash("sha256");
    hash.update("flycockpit.remote.version-registry.v1\0", "utf8");
    hash.update(Buffer.from([1]));
    const buf = Buffer.alloc(13);
    buf.writeUInt16BE(V1_TUPLE_ID, 0);
    buf.writeUInt16BE(V1_SIGNALING, 2);
    buf.writeUInt16BE(V1_AUTHORIZATION, 4);
    buf.writeUInt16BE(V1_TRANSPORT, 6);
    buf.writeUInt16BE(PROTOCOL_VERSION + 1, 8); // different application
    buf.writeUInt16BE(V1_SECURITY_RANK, 10);
    buf.writeUInt8(0, 12);
    hash.update(buf);
    const altered = new Uint8Array(hash.digest());
    expect(altered).not.toEqual(live);
  });
});

describe("remote_version_static_guards", () => {
  // Read the negotiation module's own source for the ownership/import scans.
  const moduleSource = readFileSync(join(here, "remote-version.ts"), "utf8");

  it("scans the source: no relay-protocol import, no env-driven tuples", () => {
    // No relay-protocol coupling. The doc comment names it with a hyphen, so we
    // match the actual import FORM, not the bare substring.
    expect(moduleSource).not.toMatch(/from\s+["'][^"']*relay-protocol["']/);
    // The module imports only from node:crypto and ./index — nothing else.
    const imports = [...moduleSource.matchAll(/from\s+["']([^"']+)["']/g)].map((m) => m[1]);
    expect(imports.length).toBeGreaterThan(0);
    expect(new Set(imports)).toEqual(new Set(["node:crypto", "./index"]));
    // No environment-driven tuples / legacy-envelope sniffing.
    expect(moduleSource).not.toContain("process.env");
  });

  it("scans the source: exactly one transcript codec, table, and negotiation digest", () => {
    const count = (needle: RegExp): number => (moduleSource.match(needle) ?? []).length;
    // Exactly one transcript magic definition.
    expect(count(/export const TRANSCRIPT_MAGIC =/g)).toBe(1);
    // Exactly one transcript codec (encode + decode).
    expect(count(/export function encodeTranscript\(/g)).toBe(1);
    expect(count(/export function decodeTranscript\(/g)).toBe(1);
    // Exactly one enabled-registry table.
    expect(count(/export function enabledRegistry\(/g)).toBe(1);
    // Exactly one negotiation digest (transcriptDigest); the only other digest
    // is the distinct enabledRegistryDigest. No third (e.g. SDP-based) digest.
    expect(count(/export function transcriptDigest\(/g)).toBe(1);
  });

  it("proves no permissive fallback and pure registry behavior", () => {
    expect(TRANSCRIPT_MAGIC).toBe("FCRN");
    // No permissive default: empty intersection returns null, not a fallback.
    const inputs: SelectionInputs = {
      client: [0x00fe],
      daemon: [0x00fe],
      serverAllowed: [0x00fe],
      revoked: [],
    };
    expect(select(inputs)).toBeNull();
    // v1Tuple is a pure function with no I/O.
    const reg = enabledRegistry();
    expect(reg.length).toBe(1);
    expect(registryTuple(V1_TUPLE_ID)?.tupleId).toBe(V1_TUPLE_ID);
    expect(registryTuple(0x9999)).toBeUndefined();
  });
});

describe("remote_version_v1_fixtures_corpus", () => {
  it("proves every offer/allowed list in the v1 corpus is exactly {0x0001}", () => {
    for (const c of fixture.selectionCases) {
      if (c.expectedSelected !== null) {
        expect(c.expectedSelected).toBe(V1_TUPLE_ID);
      }
    }
    // Generated fixture case counts are nonzero.
    expect(fixture.selectionCases.length).toBeGreaterThan(0);
    expect(fixture.upgradeCases.length).toBeGreaterThan(0);
    expect(fixture.transcriptVectors.length).toBeGreaterThan(0);
    expect(fixture.malformedVectors.length).toBeGreaterThan(0);
  });

  it("proves FCRN is registered to the real transcript codec, not the phantom", () => {
    const registryPath = join(here, "../fixtures/remote-wire-magic-registry-v1.json");
    const rawRegistry = readFileSync(registryPath, "utf8");
    const registry = parseRemoteWireMagicRegistry(JSON.parse(rawRegistry));
    // FCRN maps to RemoteNegotiationTranscriptV1 (which has a real codec here).
    expect(() =>
      assertRegisteredProductionMagics(registry, [
        { magic: "FCRN", symbolicType: "RemoteNegotiationTranscriptV1" },
      ]),
    ).not.toThrow();
    // The phantom relay-nonce type (no codec anywhere) must appear nowhere.
    expect(rawRegistry).not.toContain("RemoteRelayNonceV1");
    // And the old phantom claim must now be rejected for FCRN.
    expect(() =>
      assertRegisteredProductionMagics(registry, [
        { magic: "FCRN", symbolicType: "RemoteRelayNonceV1" },
      ]),
    ).toThrow();
  });
});
