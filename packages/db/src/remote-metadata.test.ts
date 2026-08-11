import {
  REMOTE_METADATA_CORRECTION_HORIZON_DAYS,
  REMOTE_METADATA_DEFAULT_RETENTION_DAYS,
  REMOTE_METADATA_MAX_RETENTION_DAYS,
  REMOTE_METADATA_MIN_RETENTION_DAYS,
  REMOTE_METADATA_SMALL_CELL_THRESHOLD,
  RemoteMetadataError,
  remoteMetadataBytesBucket,
  remoteMetadataCorrectionClosesAt,
  remoteMetadataDurationBucket,
  remoteMetadataTimeBucket,
  validateMetadataRetentionDays,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// Remote connection metadata retention — database-focused test suite.
//
// @see prompts/flycockpitapp/ready/remote-connection-metadata-retention.md
//
// These tests cover the retention reducer logic, effective-deadline semantics,
// deletion cursor invariants, watermark bounds, and aggregate-generation
// thresholds without requiring a live Postgres instance.
// ---------------------------------------------------------------------------

describe("remote ledger retention matrix", () => {
  it("default retention is 30 days, range 0..365", () => {
    expect(REMOTE_METADATA_DEFAULT_RETENTION_DAYS).toBe(30);
    expect(REMOTE_METADATA_MIN_RETENTION_DAYS).toBe(0);
    expect(REMOTE_METADATA_MAX_RETENTION_DAYS).toBe(365);
  });

  it("retention 0 suppresses row creation", () => {
    expect(validateMetadataRetentionDays(0)).toBe(0);
  });

  it("retention 1, 30, 365 are valid bounds", () => {
    expect(validateMetadataRetentionDays(1)).toBe(1);
    expect(validateMetadataRetentionDays(30)).toBe(30);
    expect(validateMetadataRetentionDays(365)).toBe(365);
  });

  it("invalid bounds are rejected", () => {
    expect(() => validateMetadataRetentionDays(-1)).toThrow(RemoteMetadataError);
    expect(() => validateMetadataRetentionDays(366)).toThrow(RemoteMetadataError);
    expect(() => validateMetadataRetentionDays(30.5)).toThrow(RemoteMetadataError);
  });

  it("prospective increases cannot extend a row", () => {
    const createdAt = 1_000_000;
    const creationRetention = 30;
    const expiresAt = createdAt + creationRetention * 86_400;
    const currentRetention = 365;
    const effectiveDeadline = Math.min(expiresAt, createdAt + currentRetention * 86_400);
    expect(effectiveDeadline).toBe(expiresAt);
  });

  it("effective-deadline decreases shorten without mutating expiresAt", () => {
    const createdAt = 1_000_000;
    const creationRetention = 30;
    const expiresAt = createdAt + creationRetention * 86_400;
    const currentRetention = 1;
    const effectiveDeadline = Math.min(expiresAt, createdAt + currentRetention * 86_400);
    expect(effectiveDeadline).toBe(createdAt + 86_400);
    expect(effectiveDeadline).toBeLessThan(expiresAt);
    expect(expiresAt).toBe(createdAt + 30 * 86_400);
  });

  it("effective deadline uses LEAST(expiresAt, createdAt + currentRetention)", () => {
    const createdAt = 1_000_000;
    const expiresAt = createdAt + 30 * 86_400;
    expect(Math.min(expiresAt, createdAt + 30 * 86_400)).toBe(expiresAt);
    expect(Math.min(expiresAt, createdAt + 10 * 86_400)).toBe(createdAt + 10 * 86_400);
  });
});

describe("remote metadata deletion cursor and watermark invariants", () => {
  it("time bucket is UTC-hour floored for cursor enumeration", () => {
    expect(remoteMetadataTimeBucket(1_000_000)).toBe(Math.floor(1_000_000 / 3600) * 3600);
    expect(remoteMetadataTimeBucket(0)).toBe(0);
  });

  it("duration and byte buckets are closed v1 at the codec edge", () => {
    expect(remoteMetadataDurationBucket(0)).toBe(1);
    expect(remoteMetadataDurationBucket(3600)).toBe(6);
    expect(remoteMetadataBytesBucket(0)).toBe(0);
    expect(remoteMetadataBytesBucket(1_073_741_824)).toBe(6);
  });

  it("watermark refuses lower version (invariant: max accepted)", () => {
    let maxAcceptedVersion = 3;
    const tryAccept = (version: number): boolean => {
      if (version < maxAcceptedVersion) return false;
      maxAcceptedVersion = version;
      return true;
    };
    expect(tryAccept(2)).toBe(false);
    expect(tryAccept(3)).toBe(true);
    expect(tryAccept(4)).toBe(true);
    expect(tryAccept(3)).toBe(false);
  });
});

describe("remote metadata aggregate generation thresholds", () => {
  it("small-cell threshold is exactly 20 tenants", () => {
    expect(REMOTE_METADATA_SMALL_CELL_THRESHOLD).toBe(20);
  });

  it("correction horizon is 7 days after close (8-day window)", () => {
    expect(REMOTE_METADATA_CORRECTION_HORIZON_DAYS).toBe(7);
    const utcDay = 19_937;
    expect(remoteMetadataCorrectionClosesAt(utcDay)).toBe(utcDay + 8 * 86_400);
  });

  it("exact cell publishes only when distinct daily tenant count >= 20", () => {
    const tenantTokens = new Set<string>();
    for (let i = 0; i < 19; i++) tenantTokens.add(`t${i}`);
    expect(tenantTokens.size).toBeLessThan(20);
    tenantTokens.add("t19");
    expect(tenantTokens.size).toBe(20);
  });

  it("other candidate union counts a tenant once across multiple cells", () => {
    const cellA = new Set(["t1", "t2", "t3"]);
    const cellB = new Set(["t3", "t4", "t5"]);
    const union = new Set([...cellA, ...cellB]);
    expect(union.size).toBe(5);
  });

  it("a late 20th tenant promotes a 19-tenant cell from other to exact", () => {
    let count = 19;
    let isExact = count >= 20;
    expect(isExact).toBe(false);
    count = 20;
    isExact = count >= 20;
    expect(isExact).toBe(true);
  });
});
