/**
 * Generates `fixtures/remote/version-negotiation-v1.json` from the live
 * registry and transcript codec. Reads the PROTOCOL_VERSION constant at
 * generation time; no fixture value hardcodes the application version.
 */
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  encodeTranscript,
  PROTOCOL_VERSION,
  type RemoteNegotiationTranscriptV1,
  type SelectionInputs,
  select,
  TRANSPORT_WEBRTC,
  TRANSPORT_WEBSOCKET_DATA,
  upgradeRequired,
  V1_TUPLE_ID,
} from "../src/index";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(here, "../fixtures/remote/version-negotiation-v1.json");

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

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

// Selection cases
const selectionCases: Array<{
  name: string;
  client: number[];
  daemon: number[];
  serverAllowed: number[];
  revoked: number[];
  expectedSelected: number | null;
}> = [
  {
    name: "all_agree_v1",
    client: [V1_TUPLE_ID],
    daemon: [V1_TUPLE_ID],
    serverAllowed: [V1_TUPLE_ID],
    revoked: [],
    expectedSelected: V1_TUPLE_ID,
  },
  {
    name: "server_disallows",
    client: [V1_TUPLE_ID],
    daemon: [V1_TUPLE_ID],
    serverAllowed: [0x00ff],
    revoked: [],
    expectedSelected: null,
  },
  {
    name: "client_lacks",
    client: [0x00fe],
    daemon: [V1_TUPLE_ID],
    serverAllowed: [V1_TUPLE_ID],
    revoked: [],
    expectedSelected: null,
  },
  {
    name: "daemon_lacks",
    client: [V1_TUPLE_ID],
    daemon: [0x00fe],
    serverAllowed: [V1_TUPLE_ID],
    revoked: [],
    expectedSelected: null,
  },
  {
    name: "v1_revoked",
    client: [V1_TUPLE_ID],
    daemon: [V1_TUPLE_ID],
    serverAllowed: [V1_TUPLE_ID],
    revoked: [V1_TUPLE_ID],
    expectedSelected: null,
  },
  {
    name: "all_unknown",
    client: [0x00fe],
    daemon: [0x00fe],
    serverAllowed: [0x00ff],
    revoked: [],
    expectedSelected: null,
  },
];

// Upgrade cases
const upgradeCases: Array<{
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
}> = [
  {
    name: "server_policy_p_nonempty",
    client: [V1_TUPLE_ID],
    daemon: [V1_TUPLE_ID],
    serverAllowed: [0x00ff],
    revoked: [],
    expectedUpgradeSide: "server_policy",
    expectedRecommended: V1_TUPLE_ID,
    expectedClientSupported: [V1_TUPLE_ID],
    expectedDaemonSupported: [V1_TUPLE_ID],
    expectedServerAllowed: [],
  },
  {
    name: "server_policy_s_empty_p_empty",
    client: [0x00fe],
    daemon: [0x00fe],
    serverAllowed: [0x00ff],
    revoked: [],
    expectedUpgradeSide: "server_policy",
    expectedRecommended: null,
    expectedClientSupported: [],
    expectedDaemonSupported: [],
    expectedServerAllowed: [],
  },
  {
    name: "client_needs_upgrade",
    client: [0x00fe],
    daemon: [V1_TUPLE_ID],
    serverAllowed: [V1_TUPLE_ID],
    revoked: [],
    expectedUpgradeSide: "client",
    expectedRecommended: V1_TUPLE_ID,
    expectedClientSupported: [],
    expectedDaemonSupported: [V1_TUPLE_ID],
    expectedServerAllowed: [V1_TUPLE_ID],
  },
  {
    name: "daemon_needs_upgrade",
    client: [V1_TUPLE_ID],
    daemon: [0x00fe],
    serverAllowed: [V1_TUPLE_ID],
    revoked: [],
    expectedUpgradeSide: "daemon",
    expectedRecommended: V1_TUPLE_ID,
    expectedClientSupported: [V1_TUPLE_ID],
    expectedDaemonSupported: [],
    expectedServerAllowed: [V1_TUPLE_ID],
  },
  {
    name: "both_need_upgrade",
    client: [0x00fe],
    daemon: [0x00fd],
    serverAllowed: [V1_TUPLE_ID],
    revoked: [],
    expectedUpgradeSide: "multiple",
    expectedRecommended: V1_TUPLE_ID,
    expectedClientSupported: [],
    expectedDaemonSupported: [],
    expectedServerAllowed: [V1_TUPLE_ID],
  },
  {
    name: "v1_revoked",
    client: [V1_TUPLE_ID],
    daemon: [V1_TUPLE_ID],
    serverAllowed: [V1_TUPLE_ID],
    revoked: [V1_TUPLE_ID],
    expectedUpgradeSide: "server_policy",
    expectedRecommended: null,
    expectedClientSupported: [],
    expectedDaemonSupported: [],
    expectedServerAllowed: [],
  },
];

// Transcript vectors
const transcriptVectors: Array<{
  name: string;
  transcriptHex: string;
  expectedDigestHex: string;
  expectedLen: number;
}> = [];

for (const [name, transport] of [
  ["webrtc", TRANSPORT_WEBRTC],
  ["websocket_data", TRANSPORT_WEBSOCKET_DATA],
] as const) {
  const t = makeTranscript(transport);
  const bytes = encodeTranscript(t);
  const digest = createHash("sha256").update(bytes).digest();
  transcriptVectors.push({
    name,
    transcriptHex: hex(bytes),
    expectedDigestHex: hex(new Uint8Array(digest)),
    expectedLen: bytes.length,
  });
}

// Malformed vectors — build from a valid V1 transcript then corrupt it.
const validTranscript = makeTranscript(TRANSPORT_WEBRTC);
const validBytes = encodeTranscript(validTranscript);

function corrupt(
  mutate: (bytes: Uint8Array) => Uint8Array,
  rejection: string,
  name: string,
): { name: string; transcriptHex: string; rejection: string } {
  const corrupted = mutate(validBytes.slice());
  return { name, transcriptHex: hex(corrupted), rejection };
}

const malformedVectors = [
  // Truncated (remove last byte).
  corrupt((b) => b.slice(0, b.length - 1), "length", "truncated"),
  // Trailing byte.
  corrupt(
    (b) => {
      const out = new Uint8Array(b.length + 1);
      out.set(b);
      out[b.length] = 0x00;
      return out;
    },
    "length",
    "trailing_byte",
  ),
  // Bad magic.
  corrupt(
    (b) => {
      b[0] = 0x58; // 'X'
      return b;
    },
    "preamble",
    "bad_magic",
  ),
  // Bad version.
  corrupt(
    (b) => {
      b[4] = 2;
      return b;
    },
    "preamble",
    "bad_version",
  ),
  // Reserved transport (0).
  corrupt(
    (b) => {
      b[5] = 0;
      return b;
    },
    "discriminant",
    "reserved_transport_zero",
  ),
  // Reserved transport (3).
  corrupt(
    (b) => {
      b[5] = 3;
      return b;
    },
    "discriminant",
    "reserved_transport_three",
  ),
  // clientCount too large (17).
  corrupt(
    (b) => {
      b[134] = 17;
      return b;
    },
    "length",
    "client_count_oversize",
  ),
  // featureCount too large (33).
  corrupt(
    (b) => {
      b[145] = 33;
      return b;
    },
    "length",
    "feature_count_oversize",
  ),
  // Zero selected tuple ID (overwrite at offset 143..145).
  corrupt(
    (b) => {
      b[143] = 0;
      b[144] = 0;
      return b;
    },
    "invalid",
    "zero_selected_id",
  ),
];

// Verify selection and upgrade cases produce expected results.
for (const c of selectionCases) {
  const inputs: SelectionInputs = {
    client: c.client,
    daemon: c.daemon,
    serverAllowed: c.serverAllowed,
    revoked: c.revoked,
  };
  const result = select(inputs);
  if ((result?.tupleId ?? null) !== c.expectedSelected) {
    throw new Error(
      `selection case ${c.name}: expected ${c.expectedSelected}, got ${result?.tupleId ?? null}`,
    );
  }
}

for (const c of upgradeCases) {
  const inputs: SelectionInputs = {
    client: c.client,
    daemon: c.daemon,
    serverAllowed: c.serverAllowed,
    revoked: c.revoked,
  };
  const result = upgradeRequired(inputs);
  if (result.upgradeSide !== c.expectedUpgradeSide) {
    throw new Error(
      `upgrade case ${c.name}: expected side ${c.expectedUpgradeSide}, got ${result.upgradeSide}`,
    );
  }
}

const fixture = {
  version: 1,
  protocolVersion: PROTOCOL_VERSION,
  registry: {
    v1TupleId: V1_TUPLE_ID,
    v1Signaling: 1,
    v1Authorization: 1,
    v1Transport: 1,
    v1Application: PROTOCOL_VERSION,
    v1SecurityRank: 100,
    v1FeatureCount: 0,
  },
  selectionCases,
  upgradeCases,
  transcriptVectors,
  malformedVectors,
  // The enabled-registry digest is never checked in: every comparison against
  // the live registry is computed at test time in both languages.
};

writeFileSync(fixturePath, JSON.stringify(fixture, null, 2) + "\n");
console.log(`Wrote ${fixturePath}`);
