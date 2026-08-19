import type { RedisClient } from "@flycockpit/api/lib/remote-authority-storage";
import type prismaType from "@flycockpit/db";
import type { env as envType } from "@flycockpit/env/server";
import { describe, expect, it } from "vitest";
import {
  authorityReadiness,
  createServerRemoteAuthority,
  type ServerRemoteAuthority,
} from "./remote-authority-runtime";

// All remote-authority vars unset — the unconfigured wiring path. prisma/redis are
// never touched on this path, so opaque placeholders are safe.
const unconfiguredEnv = (
  nodeEnv: "development" | "production",
  profile: "oss" | "hosted" | "enterprise",
) =>
  ({
    NODE_ENV: nodeEnv,
    DEPLOYMENT_PROFILE: profile,
    REMOTE_GRANT_SIGNING_KEY_FILE: undefined,
    REMOTE_AUTHORITY_ISSUER: undefined,
    REMOTE_AUTHORITY_DEPLOYMENT_ID: undefined,
    REMOTE_GRANT_SIGNING_KEY_DIGESTS: undefined,
    REMOTE_AUTHORITY_REPLICA_ID: undefined,
  }) as unknown as typeof envType;

const deps = (env: typeof envType) => ({
  env,
  prisma: {} as unknown as typeof prismaType,
  redis: {} as unknown as RedisClient,
});

describe("createServerRemoteAuthority readiness", () => {
  it("fails closed (not silently true) when authority is required but unconfigured", () => {
    for (const profile of ["hosted", "enterprise"] as const) {
      const result = createServerRemoteAuthority(deps(unconfiguredEnv("development", profile)));
      expect(result.runtime).toBeUndefined();
      expect(result.disabled).toBe(false);
      // The regression this guards: a missing runtime MUST NOT report a healthy `true`.
      expect(authorityReadiness(result)).toBe(false);
      expect(authorityReadiness(result)).not.toBe(true);
    }
  });

  it("reports an explicit disabled mode for OSS/local", () => {
    const result = createServerRemoteAuthority(deps(unconfiguredEnv("development", "oss")));
    expect(result.runtime).toBeUndefined();
    expect(result.disabled).toBe(true);
    expect(authorityReadiness(result)).toBe("disabled");
  });

  it("refuses to boot when authority is unconfigured in production", () => {
    expect(() =>
      createServerRemoteAuthority(deps(unconfiguredEnv("production", "hosted"))),
    ).toThrow("required in production");
  });

  it("rejects a partial configuration", () => {
    const env = {
      ...unconfiguredEnv("development", "hosted"),
      REMOTE_GRANT_SIGNING_KEY_FILE: "/keys/ring.json",
    } as unknown as typeof envType;
    expect(() => createServerRemoteAuthority(deps(env))).toThrow("configured together");
  });
});

describe("authorityReadiness mapping", () => {
  it("follows an active runtime's rollout decision and never invents readiness", () => {
    const active = (ready: boolean): ServerRemoteAuthority =>
      ({ runtime: { decision: { ready } }, disabled: false }) as unknown as ServerRemoteAuthority;
    expect(authorityReadiness(active(true))).toBe(true);
    expect(authorityReadiness(active(false))).toBe(false);
  });
});
