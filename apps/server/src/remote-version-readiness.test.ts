import { enabledRegistryDigest } from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";

import { getRemoteVersionReadiness } from "./remote-version-readiness.js";

describe("remote_version_replica_registry_digest", () => {
  it("proves /ready publishes the exact helper-computed digest", () => {
    const readiness = getRemoteVersionReadiness();
    const liveDigest = enabledRegistryDigest();
    const liveHex = Array.from(liveDigest, (b) => b.toString(16).padStart(2, "0")).join("");
    expect(readiness.registryDigestHex).toBe(liveHex);
    expect(readiness.registryDigestHex).toHaveLength(64);
    expect(readiness.transcriptMagic).toBe("FCRN");
    expect(readiness.transcriptVersion).toBe(1);
  });

  it("is deterministic across calls", () => {
    const a = getRemoteVersionReadiness();
    const b = getRemoteVersionReadiness();
    expect(a).toEqual(b);
  });
});
