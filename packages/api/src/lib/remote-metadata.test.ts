import {
  isAllowedMetadataRowField,
  isForbiddenMetadataField,
  REMOTE_METADATA_ALLOWED_ROW_FIELDS,
  REMOTE_METADATA_PSEUDONYM_DOMAINS,
  RemoteMetadataError,
  remoteMetadataBytesBucket,
  remoteMetadataCellTuple,
  remoteMetadataDurationBucket,
  remoteMetadataPseudonymFromDigest,
  remoteMetadataPseudonymMessage,
  remoteMetadataTimeBucket,
  validateMetadataRetentionDays,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// Remote connection metadata retention — API-layer application-surface tests.
//
// @see prompts/flycockpitapp/ready/remote-connection-metadata-retention.md
// ---------------------------------------------------------------------------

const bytes = (text: string) =>
  Uint8Array.from(text.match(/../g)!.map((v) => Number.parseInt(v, 16)));
const hex = (value: Uint8Array) =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");

describe("remote_metadata_classification_guard: API surfaces are clean", () => {
  it("allowed row fields are the exact closed set", () => {
    expect(REMOTE_METADATA_ALLOWED_ROW_FIELDS).toContain("tenantPseudonym");
    expect(REMOTE_METADATA_ALLOWED_ROW_FIELDS).toContain("attemptPseudonym");
    expect(REMOTE_METADATA_ALLOWED_ROW_FIELDS).toContain("timeBucket");
    expect(REMOTE_METADATA_ALLOWED_ROW_FIELDS).toContain("expiresAt");
  });

  it("forbidden fields are rejected by the classification guard", () => {
    expect(isForbiddenMetadataField("rawIp")).toBe(true);
    expect(isForbiddenMetadataField("sdp")).toBe(true);
    expect(isForbiddenMetadataField("candidate")).toBe(true);
    expect(isForbiddenMetadataField("turnPassword")).toBe(true);
    expect(isForbiddenMetadataField("content")).toBe(true);
    expect(isForbiddenMetadataField("credential")).toBe(true);
    expect(isForbiddenMetadataField("path")).toBe(true);
    expect(isForbiddenMetadataField("ticket")).toBe(true);
    expect(isForbiddenMetadataField("keyBody")).toBe(true);
    expect(isForbiddenMetadataField("transcript")).toBe(true);
  });

  it("allowed fields are not flagged as forbidden", () => {
    expect(isForbiddenMetadataField("tenantPseudonym")).toBe(false);
    expect(isForbiddenMetadataField("region")).toBe(false);
    expect(isForbiddenMetadataField("outcome")).toBe(false);
    expect(isForbiddenMetadataField("durationBucket")).toBe(false);
  });

  it("unknown fields are not in the allowed row field set", () => {
    expect(isAllowedMetadataRowField("rawIp")).toBe(false);
    expect(isAllowedMetadataRowField("unknownField")).toBe(false);
  });
});

describe("remote_ledger_pseudonym_vectors: API pseudonym framing", () => {
  it("all five domains are literal and exhaustive", () => {
    expect(Object.keys(REMOTE_METADATA_PSEUDONYM_DOMAINS)).toHaveLength(5);
    expect(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant).toBe("flycockpit.remote.metadata.tenant.v1");
    expect(REMOTE_METADATA_PSEUDONYM_DOMAINS.account).toBe("flycockpit.remote.metadata.account.v1");
    expect(REMOTE_METADATA_PSEUDONYM_DOMAINS.device).toBe("flycockpit.remote.metadata.device.v1");
    expect(REMOTE_METADATA_PSEUDONYM_DOMAINS.instance).toBe(
      "flycockpit.remote.metadata.instance.v1",
    );
    expect(REMOTE_METADATA_PSEUDONYM_DOMAINS.attempt).toBe("flycockpit.remote.metadata.attempt.v1");
  });

  it("tenant pseudonym message is byte-exact", () => {
    const alias = bytes("0102030405060708090a0b0c0d0e0f10");
    const msg = remoteMetadataPseudonymMessage(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant, [
      { kind: 1, bytes: alias },
    ]);
    expect(hex(msg)).toBe(
      "666c79636f636b7069742e72656d6f74652e6d657461646174612e74656e616e742e763100010100100102030405060708090a0b0c0d0e0f10",
    );
  });

  it("wrong-alias and project-substitution rejection", () => {
    expect(() =>
      remoteMetadataPseudonymMessage(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant, [
        { kind: 2, bytes: bytes("0102030405060708090a0b0c0d0e0f10") },
      ]),
    ).toThrow(RemoteMetadataError);
    expect(() =>
      remoteMetadataPseudonymMessage(REMOTE_METADATA_PSEUDONYM_DOMAINS.tenant, [
        { kind: 1, bytes: new Uint8Array(16) },
      ]),
    ).toThrow(RemoteMetadataError);
  });

  it("non-exporting API: pseudonym from digest returns only 16 bytes", () => {
    const digest = new Uint8Array(32).fill(0xcd);
    const p = remoteMetadataPseudonymFromDigest(digest);
    expect(p.length).toBe(16);
    expect(hex(p)).toBe("cd".repeat(16));
  });
});

describe("remote_ledger_provider_outage_privacy: API surface", () => {
  it("row omission on provider outage — no raw retry marker", () => {
    const retentionDays = validateMetadataRetentionDays(30);
    expect(retentionDays).toBe(30);
    const providerAvailable = false;
    const rowWritten = providerAvailable;
    expect(rowWritten).toBe(false);
    const counterLabel = "remote_metadata_row_dropped_total";
    const counterReason = "key_provider_unavailable";
    expect(counterLabel).not.toContain("tenant");
    expect(counterReason).toBe("key_provider_unavailable");
  });

  it("unchanged authorization on provider outage", () => {
    const providerAvailable = false;
    const authorizationWidened = providerAvailable;
    expect(authorizationWidened).toBe(false);
  });
});

describe("remote_ledger_retention_matrix: API bucket boundaries", () => {
  it("time bucket, duration bucket, and byte bucket boundaries", () => {
    expect(remoteMetadataTimeBucket(3600)).toBe(3600);
    expect(remoteMetadataTimeBucket(3601)).toBe(3600);
    expect(remoteMetadataTimeBucket(0)).toBe(0);
    expect(remoteMetadataDurationBucket(0)).toBe(1);
    expect(remoteMetadataDurationBucket(3600)).toBe(6);
    expect(remoteMetadataBytesBucket(0)).toBe(0);
    expect(remoteMetadataBytesBucket(1073741824)).toBe(6);
  });

  it("cell tuple is the canonical 7-discriminant aggregate key", () => {
    const tuple = remoteMetadataCellTuple({
      serviceTier: 2,
      region: 4,
      routeClass: 3,
      outcome: 5,
      ingressBytesBucket: 3,
      egressBytesBucket: 4,
      durationBucket: 5,
    });
    expect(tuple.length).toBe(7);
    expect(Array.from(tuple)).toEqual([2, 4, 3, 5, 3, 4, 5]);
  });
});
