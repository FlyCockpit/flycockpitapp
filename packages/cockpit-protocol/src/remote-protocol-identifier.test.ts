import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CompactSign, compactVerify, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";

import {
  asCanonicalU64DecimalString,
  canonicalizeRfc8785,
  canonicalU64DecimalStringSchema,
  decodeProtocolIdBase64Url,
  decodeProtocolIdBase64UrlAsKind,
  decodeU64Be,
  encodeProtocolIdBase64Url,
  encodeU64Be,
  formatCanonicalU64DecimalString,
  parseCanonicalU64DecimalString,
  parseSignedUnixTimestampDecimalString,
  protocolIdKindOf,
  REMOTE_PROTOCOL_ID_B64URL_LEN,
  REMOTE_PROTOCOL_ID_BYTES,
  rejectNumberForExactInteger,
  tagProtocolIdBytes,
  U64_MAX,
} from "./remote-protocol-id";

const here = dirname(fileURLToPath(import.meta.url));
/** flycockpitapp monorepo root (packages/cockpit-protocol/src → ../../..) */
const monorepoRoot = join(here, "../../..");
/** packages/ root for sibling schema access */
const packagesRoot = join(here, "../..");

describe("remote_protocol_identifier_grounding_fails_first", () => {
  it("proves pinned Prisma CUID/CUID2 application keys cannot be raw 16-byte protocol IDs", () => {
    // Fail-first grounding: pin real models that use @default(cuid(2)) before any mapping
    // could treat those keys as protocol aliases.
    const schemaDir = join(packagesRoot, "db/prisma/schema");
    const auth = readFileSync(join(schemaDir, "auth.prisma"), "utf8");
    const instances = readFileSync(join(schemaDir, "instances.prisma"), "utf8");
    const enterprise = readFileSync(join(schemaDir, "enterprise.prisma"), "utf8");

    expect(auth).toMatch(/model User\s*\{[\s\S]*?@id\s+@default\(cuid\(2\)\)/);
    expect(instances).toMatch(/model CockpitInstance\s*\{[\s\S]*?@id\s+@default\(cuid\(2\)\)/);
    expect(enterprise).toMatch(/model EnterpriseOrg\s*\{[\s\S]*?@id\s+@default\(cuid\(2\)\)/);

    // Mapping model must exist and store protocolId as Bytes, sourceId as String.
    const remote = readFileSync(join(schemaDir, "remote-protocol.prisma"), "utf8");
    expect(remote).toMatch(/model RemoteProtocolIdentifier/);
    expect(remote).toMatch(/protocolId\s+Bytes/);
    expect(remote).toMatch(/sourceId\s+String/);
    expect(remote).toMatch(/@@unique\(\[kind,\s*sourceId\]\)/);

    // cuid(2) UTF-8 strings are not 16 raw bytes and fail protocol codecs before mapping.
    const cuid2Like = [
      "lkq8z3m9n2p4q5r6s7t8u9v0",
      "cm5examplecuid2sourceid01",
      "clxxxxxxxxxxxxxxxxxxxx",
    ];
    for (const id of cuid2Like) {
      const utf8 = new TextEncoder().encode(id);
      expect(utf8.length).not.toBe(REMOTE_PROTOCOL_ID_BYTES);
      expect(() => decodeProtocolIdBase64Url(id)).toThrow();
      expect(() => encodeProtocolIdBase64Url(utf8)).toThrow();
    }
  });

  it("proves JSON numbers corrupt values above 2^53-1", () => {
    const cases = [2n ** 53n + 1n, U64_MAX];
    for (const v of cases) {
      const asNumber = Number(v);
      expect(BigInt(Math.trunc(asNumber)) === v).toBe(false);
      const s = formatCanonicalU64DecimalString(v);
      expect(parseCanonicalU64DecimalString(s)).toBe(v);
    }
    expect(parseCanonicalU64DecimalString(formatCanonicalU64DecimalString(2n ** 53n))).toBe(
      2n ** 53n,
    );
  });
});

describe("remote_protocol_identifier_cross_language_vectors", () => {
  it("matches checked shared fixture bytes/base64url and u64 boundaries", async () => {
    const vectors = await import("../fixtures/remote-protocol-id-vectors.json");
    const hex = vectors.protocol_id_bytes_hex as string;
    const bytes = new Uint8Array(hex.match(/.{2}/g)!.map((h) => Number.parseInt(h, 16)));
    expect(encodeProtocolIdBase64Url(bytes)).toBe(vectors.protocol_id_b64url);
    expect(Array.from(decodeProtocolIdBase64Url(vectors.protocol_id_b64url))).toEqual(
      Array.from(bytes),
    );
    const u64 = vectors.u64_boundaries as Record<string, string>;
    expect(parseCanonicalU64DecimalString(u64["0"]!)).toBe(0n);
    expect(parseCanonicalU64DecimalString(u64["1"]!)).toBe(1n);
    expect(parseCanonicalU64DecimalString(u64["2_53_minus_1"]!)).toBe(2n ** 53n - 1n);
    expect(parseCanonicalU64DecimalString(u64["2_53"]!)).toBe(2n ** 53n);
    expect(parseCanonicalU64DecimalString(u64["2_53_plus_1"]!)).toBe(2n ** 53n + 1n);
    expect(parseCanonicalU64DecimalString(u64.u64_max!)).toBe(U64_MAX);
  });

  it("round-trips and enforces nominal kind separation", () => {
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) bytes[i] = i + 1;
    const text = encodeProtocolIdBase64Url(bytes);
    expect(text).toHaveLength(REMOTE_PROTOCOL_ID_B64URL_LEN);
    const tenant = tagProtocolIdBytes("tenant", bytes);
    const account = tagProtocolIdBytes("account", bytes);
    expect(protocolIdKindOf(tenant)).toBe("tenant");
    expect(protocolIdKindOf(account)).toBe("account");
    expect(protocolIdKindOf(tenant)).not.toBe(protocolIdKindOf(account));
    const asTenant = decodeProtocolIdBase64UrlAsKind("tenant", text);
    expect(protocolIdKindOf(asTenant)).toBe("tenant");
  });

  it("rejects padding, alphabet, all-zero, wrong length", () => {
    const bytes = new Uint8Array(16);
    bytes[0] = 1;
    const text = encodeProtocolIdBase64Url(bytes);
    expect(() => decodeProtocolIdBase64Url(`${text}=`)).toThrow();
    expect(() => decodeProtocolIdBase64Url(`+${text.slice(1)}`)).toThrow();
    expect(() => decodeProtocolIdBase64Url(` ${text}`)).toThrow();
    expect(() => decodeProtocolIdBase64Url(text.slice(0, 21))).toThrow();
    expect(() => encodeProtocolIdBase64Url(new Uint8Array(16))).toThrow();
    expect(() => encodeProtocolIdBase64Url(new Uint8Array(15))).toThrow();
    expect(() => tagProtocolIdBytes("tenant", new Uint8Array(16))).toThrow();
    expect(() => tagProtocolIdBytes("bogus" as "tenant", bytes)).toThrow();
  });

  it("encodes without Node Buffer (web/native safe)", () => {
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) bytes[i] = i + 1;
    // Pure codec path must not require Buffer.
    const text = encodeProtocolIdBase64Url(bytes);
    expect(text).toBe("AQIDBAUGBwgJCgsMDQ4PEA");
    expect(Array.from(decodeProtocolIdBase64Url(text))).toEqual(Array.from(bytes));
  });

  it("u64be boundary adapters round-trip", () => {
    for (const v of [0n, 1n, 2n ** 53n + 1n, U64_MAX]) {
      expect(decodeU64Be(encodeU64Be(v))).toBe(v);
    }
    expect(() => encodeU64Be(-1n)).toThrow();
    expect(() => decodeU64Be(new Uint8Array(7))).toThrow();
  });
});

describe("remote_u64_rfc8785_jws_vectors", () => {
  it("rejects JSON number and TypeScript number for exact u64 fields", () => {
    const numericJson = JSON.parse('{"seq":9007199254740993}');
    expect(() => parseCanonicalU64DecimalString(numericJson.seq)).toThrow();
    expect(() => rejectNumberForExactInteger(numericJson.seq)).toThrow();
    expect(canonicalU64DecimalStringSchema.safeParse(numericJson.seq).success).toBe(false);
    const stringJson = JSON.parse('{"seq":"9007199254740993"}');
    expect(parseCanonicalU64DecimalString(stringJson.seq)).toBe(2n ** 53n + 1n);
    expect(canonicalU64DecimalStringSchema.parse(stringJson.seq)).toBe("9007199254740993");
  });

  it("produces stable RFC8785 canonical bytes at u64 boundaries", () => {
    const boundaries = [0n, 1n, 2n ** 53n - 1n, 2n ** 53n, 2n ** 53n + 1n, U64_MAX];
    for (const v of boundaries) {
      const seq = formatCanonicalU64DecimalString(v);
      const payload = { kind: "remote-u64-v1", note: "exact", seq };
      const canonical = canonicalizeRfc8785(payload);
      // Deterministic key order: kind, note, seq
      expect(canonical).toBe(
        `{"kind":"remote-u64-v1","note":"exact","seq":${JSON.stringify(seq)}}`,
      );
      expect(canonicalizeRfc8785(JSON.parse(canonical))).toBe(canonical);
      expect(canonicalizeRfc8785({ note: "exact", kind: "remote-u64-v1", seq })).toBe(canonical);
      // Canonical bytes must not contain insignificant whitespace.
      expect(canonical.includes(" ")).toBe(false);
    }
    // Fixed vector from fixture expectations
    expect(canonicalizeRfc8785({ b: "2", a: "1" })).toBe('{"a":"1","b":"2"}');
  });

  it("signs and verifies compact JWS over exact RFC8785 payload bytes", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });

    const boundaries = [0n, 1n, 2n ** 53n - 1n, 2n ** 53n, 2n ** 53n + 1n, U64_MAX];
    const signedCanonicals: string[] = [];
    for (const v of boundaries) {
      const seq = formatCanonicalU64DecimalString(v);
      // Exact integer fields as decimal strings only — no numeric iat/exp.
      const payload = {
        kind: "remote-u64-v1",
        seq,
        iat: formatCanonicalU64DecimalString(1_700_000_000n),
      };
      const canonical = canonicalizeRfc8785(payload);
      signedCanonicals.push(canonical);
      const payloadBytes = new TextEncoder().encode(canonical);
      // Sign the exact UTF-8 RFC8785 bytes (not JSON.stringify of a JWT claims object).
      const jws = await new CompactSign(payloadBytes)
        .setProtectedHeader({ alg: "ES256", typ: "remote-u64-v1+jws" })
        .sign(privateKey);
      expect(jws.split(".")).toHaveLength(3);
      const { payload: recovered, protectedHeader } = await compactVerify(jws, publicKey);
      expect(protectedHeader.alg).toBe("ES256");
      const recoveredText = new TextDecoder().decode(recovered);
      expect(recoveredText).toBe(canonical);
      const parsed = JSON.parse(recoveredText) as { seq: string; iat: string };
      expect(parseCanonicalU64DecimalString(parsed.seq)).toBe(v);
      expect(parseSignedUnixTimestampDecimalString(parsed.iat)).toBe(1_700_000_000n);

      // Numeric claim must be rejected at our boundary.
      expect(() => parseCanonicalU64DecimalString(Number(v.toString()))).toThrow();
    }
    // Distinct boundaries produce distinct canonical payloads (stable vectors).
    expect(new Set(signedCanonicals).size).toBe(boundaries.length);

    expect(() => formatCanonicalU64DecimalString(1 as unknown as bigint)).toThrow();
    expect(asCanonicalU64DecimalString("42")).toBe("42");
  });

  it("RFC8785 rejects unsafe integer numbers, non-plain objects, and undefined", () => {
    expect(() => canonicalizeRfc8785({ seq: Number(2n ** 53n + 1n) })).toThrow();
    expect(() => canonicalizeRfc8785(new Date())).toThrow();
    expect(() => canonicalizeRfc8785({ a: undefined as unknown as string })).toThrow();
    expect(() => canonicalizeRfc8785(String.fromCharCode(0xd800))).toThrow();
    expect(() => canonicalizeRfc8785(new Array(1))).toThrow();
  });
});

describe("remote_u64_decimal_string_boundaries", () => {
  it("accepts boundary values as decimal strings", () => {
    const cases = [0n, 1n, 2n ** 53n - 1n, 2n ** 53n, 2n ** 53n + 1n, U64_MAX];
    for (const v of cases) {
      const s = formatCanonicalU64DecimalString(v);
      expect(parseCanonicalU64DecimalString(s)).toBe(v);
    }
  });

  it("rejects invalid spellings and number inputs", () => {
    const invalid = [
      "",
      "+1",
      "-1",
      "01",
      "1.0",
      "1e2",
      " 1",
      "1 ",
      "18446744073709551616",
      "99999999999999999999",
    ];
    for (const s of invalid) {
      expect(() => parseCanonicalU64DecimalString(s)).toThrow();
    }
    expect(() => parseCanonicalU64DecimalString(1 as unknown as string)).toThrow();
    expect(() => parseCanonicalU64DecimalString(Number(2n ** 53n + 1n) as unknown)).toThrow();
    expect(() => rejectNumberForExactInteger(1)).toThrow();
  });
});

describe("remote_protocol_identifier_no_raw_cuid_wire", () => {
  it("scans foundation remote packages for cuid→protocolId coercion", () => {
    const scanDirs = [
      "packages/cockpit-protocol/src",
      "packages/relay-protocol/src",
      "crates/cockpit-proto/src",
    ];
    const coercion =
      /protocolId\s*[:=]\s*.*cuid|cuid\s*\(.*\)\s*.*protocolId|Buffer\.from\(\s*[^)]*cuid/i;
    const files: string[] = [];
    const walk = (rel: string) => {
      const abs = join(monorepoRoot, rel);
      let st: ReturnType<typeof statSync>;
      try {
        st = statSync(abs);
      } catch {
        return;
      }
      if (st.isDirectory()) {
        for (const name of readdirSync(abs)) {
          if (name === "node_modules" || name === "dist") continue;
          walk(join(rel, name));
        }
        return;
      }
      if (!/\.(ts|tsx|rs)$/.test(rel)) return;
      files.push(rel);
    };
    for (const d of scanDirs) walk(d);
    expect(files.length).toBeGreaterThan(5);
    const hits: string[] = [];
    for (const rel of files) {
      if (rel.endsWith(".test.ts")) continue;
      const text = readFileSync(join(monorepoRoot, rel), "utf8");
      if (coercion.test(text)) hits.push(rel);
    }
    expect(hits).toEqual([]);
  });
});
