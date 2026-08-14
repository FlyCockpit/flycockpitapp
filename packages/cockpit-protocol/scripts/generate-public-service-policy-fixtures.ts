/**
 * Regenerate `fixtures/remote/public-service-policy-v1.json` — the shared,
 * byte-identical cross-language corpus consumed by
 * `crates/cockpit-proto/tests/remote_public_service_policy_fixtures.rs` and
 * `src/remote-public-service-policy.test.ts`.
 *
 * Run: `pnpm --filter @flycockpit/cockpit-protocol generate:public-service-policy-fixtures`.
 *
 * This generator is intentionally self-contained (Node built-ins only): the
 * conformance tests replay every vector through the REAL production codecs in
 * both languages, so any drift between this script and production is caught by
 * a failing test rather than hidden. ECDSA/P-256 is randomized, so regeneration
 * rewrites the signatures and public keys (expected, per the identity-custody
 * signing-fixture precedent); the canonical bytes, digests, and binary vectors
 * are fully deterministic. The signing keys below are TEST-ONLY and are never
 * read outside this generator.
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Small self-contained helpers (mirror the production module + Rust foundation)
// ---------------------------------------------------------------------------

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function b64urlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const has1 = i + 1 < bytes.length;
    const has2 = i + 2 < bytes.length;
    const b1 = has1 ? (bytes[i + 1] as number) : 0;
    const b2 = has2 ? (bytes[i + 2] as number) : 0;
    out += B64URL[b0 >> 2];
    out += B64URL[((b0 & 0x03) << 4) | (b1 >> 4)];
    if (has1) out += B64URL[((b1 & 0x0f) << 2) | (b2 >> 6)];
    if (has2) out += B64URL[b2 & 0x3f];
  }
  return out;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(text: string): Uint8Array {
  return Uint8Array.from((text.match(/../g) ?? []).map((p) => Number.parseInt(p, 16)));
}
const te = new TextEncoder();

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes))));
}

// RFC 8785 canonicalization (copied verbatim from the production algorithm so
// the committed corpus matches `canonicalizeRfc8785` and the Rust canonical
// JSON exactly for ASCII documents).
function canon(value: unknown): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canon).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value as Record<string, unknown>).sort();
    return `{${keys
      .map((k) => `${JSON.stringify(k)}:${canon((value as Record<string, unknown>)[k])}`)
      .join(",")}}`;
  }
  throw new Error("unsupported value");
}

// ---------------------------------------------------------------------------
// ES256 signing (low-S, matching the strict verifier in both languages)
// ---------------------------------------------------------------------------

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = N >> 1n;
const toBig = (b: Uint8Array) => b.reduce((acc, x) => (acc << 8n) | BigInt(x), 0n);
const toBytes = (v: bigint) => {
  const out = new Uint8Array(32);
  let n = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
};

interface TestKey {
  kid: string;
  role: "current" | "previous" | "next";
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  x: string;
  y: string;
}

async function makeKey(kid: string, role: TestKey["role"]): Promise<TestKey> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    kid,
    role,
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    x: jwk.x as string,
    y: jwk.y as string,
  };
}

// Sign `message` and return a low-S 64-byte raw r||s signature.
async function signLowS(key: TestKey, message: Uint8Array): Promise<Uint8Array> {
  // Normalize to a plain `Uint8Array<ArrayBuffer>` so it satisfies `BufferSource`
  // (a `Uint8Array<ArrayBufferLike>` param does not) — matching the `new
  // Uint8Array(...)` idiom used elsewhere in this file for WebCrypto inputs.
  const msg = new Uint8Array(message);
  for (;;) {
    const raw = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, msg),
    );
    const r = raw.slice(0, 32);
    const s = toBig(raw.slice(32, 64));
    if (toBig(r) === 0n || s === 0n || toBig(r) >= N) continue;
    const sLow = s > HALF_N ? N - s : s;
    if (sLow === 0n) continue;
    const out = new Uint8Array(64);
    out.set(r, 0);
    out.set(toBytes(sLow), 32);
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key.publicKey,
      out,
      msg,
    );
    if (ok) return out;
  }
}

function jwkObject(key: TestKey) {
  return {
    kid: key.kid,
    kty: "EC",
    crv: "P-256",
    x: key.x,
    y: key.y,
    use: "sig",
    key_ops: ["verify"],
    flycockpit_role: key.role,
  };
}

function header(kid: string, extra?: Record<string, unknown>) {
  return { alg: "ES256", kid, typ: "flycockpit-public-remote-policy+jws", ...extra };
}

function compactFrom(headerB64: string, payloadB64: string, sig: Uint8Array): string {
  return `${headerB64}.${payloadB64}.${b64urlEncode(sig)}`;
}

// ---------------------------------------------------------------------------
// Binary codecs (ceiling / tuple set) — deterministic vectors
// ---------------------------------------------------------------------------

function encodeCeiling(
  att: number[],
  projects: Array<{ idHex: string; caps: number[] }>,
): Uint8Array {
  const parts: number[] = [1, att.length, ...att, projects.length];
  for (const p of projects) {
    parts.push(...fromHex(p.idHex), p.caps.length, ...p.caps);
  }
  return Uint8Array.from(parts);
}

function encodeTuple(ids: number[]): Uint8Array {
  const out = new Uint8Array(1 + ids.length * 2);
  out[0] = ids.length;
  ids.forEach((id, i) => {
    out[1 + i * 2] = (id >> 8) & 0xff;
    out[2 + i * 2] = id & 0xff;
  });
  return out;
}

// ---------------------------------------------------------------------------
// Policy envelopes
// ---------------------------------------------------------------------------

const POLICY_ID = b64urlEncode(fromHex("0102030405060708090a0b0c0d0e0f10"));

function baselinePolicy() {
  return {
    allowedTransports: ["webrtc", "websocket_data"],
    directIpMode: "mutual_consent",
    sharedSessionRoute: "relay_only",
    websocketFallback: true,
    tenantAuthorization: "control_plane",
    minimumDaemonCustody: "os_protected",
    minimumClientCustody: "origin_protected",
    sharingEnabled: true,
    limits: {
      registeredDaemons: "10",
      concurrentAttachments: "5",
      concurrentChildrenPerAttachment: "3",
      concurrentParticipantsPerSession: "8",
      turnBytesPerAttachment: "10737418240",
      turnDurationSeconds: "28800",
      websocketBytesPerAttachment: "10737418240",
      websocketDurationSeconds: "28800",
    },
    allowedTurnRegions: [
      "africa",
      "asia_pacific",
      "europe",
      "local",
      "middle_east",
      "north_america",
      "oceania",
      "south_america",
    ],
    metadataRetentionDays: "30",
  };
}

// A narrowed (version 2) policy: stricter client custody, fewer regions.
function narrowedPolicy() {
  const p = baselinePolicy();
  p.minimumClientCustody = "hardware";
  p.allowedTurnRegions = ["europe", "north_america"];
  p.metadataRetentionDays = "14";
  return p;
}

function envelope(
  serviceVersion: string,
  previousDigest: string | null,
  changeClass: "narrowing_or_equal" | "widening",
  policy: unknown,
) {
  return {
    schemaVersion: 1,
    policyId: POLICY_ID,
    serviceVersion,
    previousDigest,
    issuedAt: "1000000",
    notBefore: "1000000",
    changeClass,
    policy,
  };
}

// ---------------------------------------------------------------------------
// Build the corpus
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const current = await makeKey("k-current", "current");
  const previous = await makeKey("k-previous", "previous");
  const next = await makeKey("k-next", "next");

  const baseEnvelope = envelope("1", null, "narrowing_or_equal", baselinePolicy());
  const baseCanonical = canon(baseEnvelope);
  const basePayloadB64 = b64urlEncode(te.encode(baseCanonical));

  const signWith = async (key: TestKey, extraHeader?: Record<string, unknown>) => {
    const hB64 = b64urlEncode(te.encode(canon(header(key.kid, extraHeader))));
    const signingInput = `${hB64}.${basePayloadB64}`;
    const sig = await signLowS(key, te.encode(signingInput));
    return { hB64, sig };
  };

  const jwsVectors: unknown[] = [];

  // Valid current-key import (also valid under verify_imported).
  {
    const { hB64, sig } = await signWith(current);
    jwsVectors.push({
      id: "valid_current_import",
      ring: "currentOnly",
      usage: "import",
      compact: compactFrom(hB64, basePayloadB64, sig),
      expect: "accept",
    });
    jwsVectors.push({
      id: "valid_current_reverify",
      ring: "currentOnly",
      usage: "verify_imported",
      compact: compactFrom(hB64, basePayloadB64, sig),
      expect: "accept",
    });
  }

  // Previous key: verify_imported accepts, import rejects.
  {
    const { hB64, sig } = await signWith(previous);
    const compact = compactFrom(hB64, basePayloadB64, sig);
    jwsVectors.push({
      id: "previous_reverify_accept",
      ring: "previousCurrent",
      usage: "verify_imported",
      compact,
      expect: "accept",
    });
    jwsVectors.push({
      id: "previous_import_reject",
      ring: "previousCurrent",
      usage: "import",
      compact,
      expect: "reject",
    });
  }

  // Next key: rejected under both usages.
  {
    const { hB64, sig } = await signWith(next);
    const compact = compactFrom(hB64, basePayloadB64, sig);
    jwsVectors.push({
      id: "next_import_reject",
      ring: "currentNext",
      usage: "import",
      compact,
      expect: "reject",
    });
    jwsVectors.push({
      id: "next_reverify_reject",
      ring: "currentNext",
      usage: "verify_imported",
      compact,
      expect: "reject",
    });
  }

  // Unknown kid (signed by a key absent from the ring).
  {
    const stray = await makeKey("k-stray", "current");
    const { hB64, sig } = await signWith(stray);
    jwsVectors.push({
      id: "unknown_kid",
      ring: "currentOnly",
      usage: "import",
      compact: compactFrom(hB64, basePayloadB64, sig),
      expect: "reject",
    });
  }

  // Tampered payload (valid current sig over baseline, but different payload).
  {
    const { hB64, sig } = await signWith(current);
    const otherPayload = b64urlEncode(
      te.encode(canon(envelope("2", null, "narrowing_or_equal", narrowedPolicy()))),
    );
    jwsVectors.push({
      id: "tampered_payload",
      ring: "currentOnly",
      usage: "import",
      compact: compactFrom(hB64, otherPayload, sig),
      expect: "reject",
    });
  }

  // Tampered signature (flip one byte).
  {
    const { hB64, sig } = await signWith(current);
    const bad = sig.slice();
    bad[10] = (bad[10] as number) ^ 0xff;
    jwsVectors.push({
      id: "tampered_signature",
      ring: "currentOnly",
      usage: "import",
      compact: compactFrom(hB64, basePayloadB64, bad),
      expect: "reject",
    });
  }

  // High-S variant of an otherwise valid signature.
  {
    const { hB64, sig } = await signWith(current);
    const high = sig.slice();
    high.set(toBytes(N - toBig(sig.slice(32, 64))), 32);
    jwsVectors.push({
      id: "high_s",
      ring: "currentOnly",
      usage: "import",
      compact: compactFrom(hB64, basePayloadB64, high),
      expect: "reject",
    });
  }

  // Zero-r and zero-s.
  {
    const { hB64 } = await signWith(current);
    const zeroR = new Uint8Array(64);
    zeroR[63] = 1;
    const zeroS = new Uint8Array(64);
    zeroS[0] = 1;
    jwsVectors.push({
      id: "zero_r",
      ring: "currentOnly",
      usage: "import",
      compact: compactFrom(hB64, basePayloadB64, zeroR),
      expect: "reject",
    });
    jwsVectors.push({
      id: "zero_s",
      ring: "currentOnly",
      usage: "import",
      compact: compactFrom(hB64, basePayloadB64, zeroS),
      expect: "reject",
    });
  }

  // DER-encoded signature (variable length, not 64 raw bytes).
  {
    const hB64 = b64urlEncode(te.encode(canon(header(current.kid))));
    const signingInput = `${hB64}.${basePayloadB64}`;
    const raw = await signLowS(current, te.encode(signingInput));
    // Minimal DER SEQUENCE of two INTEGERs r, s.
    const derInt = (b: Uint8Array) => {
      let i = 0;
      while (i < b.length - 1 && b[i] === 0) i++;
      let v = b.slice(i);
      if ((v[0] as number) & 0x80) v = Uint8Array.from([0, ...v]);
      return Uint8Array.from([0x02, v.length, ...v]);
    };
    const rDer = derInt(raw.slice(0, 32));
    const sDer = derInt(raw.slice(32, 64));
    const der = Uint8Array.from([0x30, rDer.length + sDer.length, ...rDer, ...sDer]);
    jwsVectors.push({
      id: "der_signature",
      ring: "currentOnly",
      usage: "import",
      compact: compactFrom(hB64, basePayloadB64, der),
      expect: "reject",
    });
  }

  // Noncanonical base64url signature (flip a spare low bit of the last char).
  {
    const { hB64, sig } = await signWith(current);
    const sigB64 = b64urlEncode(sig);
    const lastIdx = B64URL.indexOf(sigB64[sigB64.length - 1] as string);
    const noncanonical = sigB64.slice(0, -1) + B64URL[lastIdx ^ 1];
    jwsVectors.push({
      id: "noncanonical_base64url",
      ring: "currentOnly",
      usage: "import",
      compact: `${hB64}.${basePayloadB64}.${noncanonical}`,
      expect: "reject",
    });
  }

  // Header mutations.
  {
    const mutate = async (id: string, extra: Record<string, unknown>) => {
      const { hB64, sig } = await signWith(current, extra);
      jwsVectors.push({
        id,
        ring: "currentOnly",
        usage: "import",
        compact: compactFrom(hB64, basePayloadB64, sig),
        expect: "reject",
      });
    };
    await mutate("header_extra_key", { extra: true });
    // wrong typ / alg / empty kid need bespoke headers (not via header()).
    for (const [id, hdr] of [
      ["header_wrong_typ", { alg: "ES256", kid: current.kid, typ: "wrong" }],
      [
        "header_wrong_alg",
        { alg: "RS256", kid: current.kid, typ: "flycockpit-public-remote-policy+jws" },
      ],
      ["header_empty_kid", { alg: "ES256", kid: "", typ: "flycockpit-public-remote-policy+jws" }],
    ] as const) {
      const hB64 = b64urlEncode(te.encode(canon(hdr)));
      const sig = await signLowS(current, te.encode(`${hB64}.${basePayloadB64}`));
      jwsVectors.push({
        id,
        ring: "currentOnly",
        usage: "import",
        compact: compactFrom(hB64, basePayloadB64, sig),
        expect: "reject",
      });
    }
  }

  // Policy payload vectors (canonical bytes + digest).
  const nonBaseline = envelope(
    "2",
    await sha256Hex(te.encode(baseCanonical)),
    "narrowing_or_equal",
    narrowedPolicy(),
  );
  const policyVectors = [
    {
      id: "baseline_v1",
      policy: baseEnvelope,
      canonicalJson: baseCanonical,
      payloadDigestHex: await sha256Hex(te.encode(baseCanonical)),
    },
    {
      id: "narrowed_v2",
      policy: nonBaseline,
      canonicalJson: canon(nonBaseline),
      payloadDigestHex: await sha256Hex(te.encode(canon(nonBaseline))),
    },
  ];

  // Import-window vectors: exercise validate_for_import skew/window in BOTH
  // languages. `far_future_u64_max` has issuedAt/notBefore = u64::MAX; a naive
  // Rust `as i64` cast would wrap it negative and accept it, so both languages
  // must reject it as far-future (the i128/bigint comparison is the fix).
  const U64_MAX = "18446744073709551615";
  const importWindowVectors = [
    {
      id: "within_window",
      policy: baseEnvelope,
      importTime: "1000000",
      expect: "accept",
    },
    {
      id: "far_future_u64_max",
      policy: { ...baseEnvelope, issuedAt: U64_MAX, notBefore: U64_MAX },
      importTime: "1000000",
      expect: "reject",
    },
    {
      id: "issued_beyond_skew",
      policy: { ...baseEnvelope, issuedAt: "1000061", notBefore: "1000061" },
      importTime: "1000000",
      expect: "reject",
    },
  ];

  // Ceiling vectors.
  const emptyCeilingBytes = encodeCeiling([], []);
  const minCeilingBytes = encodeCeiling([1], [{ idHex: "01".repeat(16), caps: [1] }]);
  const ceilingVectors = [
    {
      id: "empty",
      kind: "struct",
      att: [],
      projects: [],
      expect: "accept",
      bytesHex: hex(emptyCeilingBytes),
      digestHex: await sha256Hex(emptyCeilingBytes),
    },
    {
      id: "minimum",
      kind: "struct",
      att: [1],
      projects: [{ idHex: "01".repeat(16), caps: [1] }],
      expect: "accept",
      bytesHex: hex(minCeilingBytes),
      digestHex: await sha256Hex(minCeilingBytes),
    },
    {
      id: "maximum_exceeds_512",
      kind: "struct",
      att: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
      projects: Array.from({ length: 16 }, (_, i) => ({
        idHex: (i + 1).toString(16).padStart(32, "0"),
        caps: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      })),
      expect: "reject",
    },
    { id: "unsorted_attachment", kind: "struct", att: [3, 1], projects: [], expect: "reject" },
    { id: "trailing_byte", kind: "bytes", bytesHex: `${hex(minCeilingBytes)}00`, expect: "reject" },
    { id: "one_byte_mutation", kind: "bytes", bytesHex: "010000ff", expect: "reject" },
  ];

  // Transport-bit vectors.
  const transportBitVectors = [
    { bits: 1, expect: "accept" },
    { bits: 2, expect: "accept" },
    { bits: 3, expect: "accept" },
    { bits: 0, expect: "reject" },
    { bits: 4, expect: "reject" },
    { bits: 255, expect: "reject" },
  ];

  // Tuple-set vectors (revocation is the key new branch).
  const validTupleBytes = encodeTuple([1]);
  const tupleSetVectors = [
    {
      id: "valid_v1",
      kind: "struct",
      tupleIds: [1],
      revoked: [],
      expect: "accept",
      bytesHex: hex(validTupleBytes),
    },
    { id: "encode_revoked_member", kind: "struct", tupleIds: [1], revoked: [1], expect: "reject" },
    {
      id: "decode_revoked_member",
      kind: "bytes",
      bytesHex: hex(validTupleBytes),
      revoked: [1],
      expect: "reject",
    },
    { id: "unknown_tuple", kind: "struct", tupleIds: [2], revoked: [], expect: "reject" },
    { id: "zero_revoked", kind: "struct", tupleIds: [1], revoked: [0], expect: "reject" },
  ];

  // Classification vectors.
  const classificationVectors = [
    {
      id: "narrowing",
      previous: baselinePolicy(),
      next: narrowedPolicy(),
      expected: "narrowing_or_equal",
    },
    {
      id: "widening",
      previous: narrowedPolicy(),
      next: baselinePolicy(),
      expected: "widening",
    },
    {
      id: "mixed",
      previous: baselinePolicy(),
      next: (() => {
        const p = baselinePolicy();
        p.limits.registeredDaemons = "20"; // widened
        p.minimumClientCustody = "hardware"; // narrowed
        return p;
      })(),
      expected: "mixed",
    },
  ];

  const fixture = {
    schemaVersion: 1,
    description:
      "Cross-language public service policy corpus: signed ES256 JWS verify verdicts, canonical payload digests, three-valued classification, ceiling/transport/tuple-set codec vectors (incl. revocation), and cross-language state/constant pins. ECDSA is randomized; signatures are regenerated on each run and verified by both languages.",
    rings: {
      currentOnly: { keys: [jwkObject(current)] },
      previousCurrent: { keys: [jwkObject(previous), jwkObject(current)] },
      currentNext: { keys: [jwkObject(current), jwkObject(next)] },
    },
    jwsVectors,
    policyVectors,
    importWindowVectors,
    u64Boundaries: {
      "2_53_minus_1": "9007199254740991",
      "2_53": "9007199254740992",
      "2_53_plus_1": "9007199254740993",
      u64_max: "18446744073709551615",
    },
    jsonNumberRejection: '{"serviceVersion":9007199254740993}',
    classificationVectors,
    ceilingVectors,
    transportBitVectors,
    tupleSetVectors,
    vocabulary: {
      policyRowStates: [
        "scheduled",
        "preparing",
        "active_converging",
        "active",
        "active_convergence_failed",
        "scheduled_failed",
      ],
      consumerGroupStates: ["disabled", "required", "draining", "retired"],
      replicaLeaseStates: ["starting", "ready", "draining", "stale"],
      criticalConsumerIds: [
        "attempt_issuer",
        "signaling_gateway",
        "daemon_authorizer",
        "turn_issuer",
        "websocket_fallback_gateway",
        "web_route_selector",
        "native_route_selector",
        "metadata_retention_worker",
      ],
      timing: {
        convergenceTimeoutSeconds: 300,
        replicaLeaseRenewSeconds: 15,
        replicaLeaseTtlSeconds: 45,
        staleReapGraceSeconds: 90,
      },
    },
  };

  const outPath = fileURLToPath(
    new URL("../fixtures/remote/public-service-policy-v1.json", import.meta.url),
  );
  writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`);
  process.stdout.write(`wrote ${outPath}\n`);
}

await main();
