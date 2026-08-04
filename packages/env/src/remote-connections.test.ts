import { describe, expect, it } from "vitest";
import {
  parseRemoteConnectionsMode,
  type RemoteConnectionMode,
  remoteConnectionCapabilities,
  remoteConnectionsFromEnvBag,
} from "./remote-connections";

describe("remote_connections_mode_defaults_and_rejects_invalid", () => {
  it("defaults omitted and empty to both", () => {
    expect(parseRemoteConnectionsMode(undefined)).toBe("both");
    expect(parseRemoteConnectionsMode(null)).toBe("both");
    expect(parseRemoteConnectionsMode("")).toBe("both");
  });

  it("accepts exact case-sensitive modes only", () => {
    expect(parseRemoteConnectionsMode("webrtc")).toBe("webrtc");
    expect(parseRemoteConnectionsMode("websocket")).toBe("websocket");
    expect(parseRemoteConnectionsMode("both")).toBe("both");
  });

  it.each([
    "Webrtc",
    "WEBRTC",
    " websocket ",
    "  ",
    "true",
    "false",
    "1",
    "webrtc,websocket",
    "relay",
    "auto",
    "unknown",
  ])("rejects invalid value %j", (raw) => {
    expect(() => parseRemoteConnectionsMode(raw)).toThrow(/REMOTE_CONNECTIONS/);
  });
});

describe("remote_connections_capability_matrix", () => {
  it("maps every mode exhaustively", () => {
    const modes: RemoteConnectionMode[] = ["webrtc", "websocket", "both"];
    const matrix = Object.fromEntries(
      modes.map((mode) => [mode, remoteConnectionCapabilities(mode)]),
    );
    expect(matrix).toEqual({
      webrtc: { webrtc: true, websocketData: false },
      websocket: { webrtc: false, websocketData: true },
      both: { webrtc: true, websocketData: true },
    });
  });
});

describe("remote_connections_signaling_is_not_a_capability_toggle", () => {
  it("capability object has only webrtc and websocketData keys", () => {
    for (const mode of ["webrtc", "websocket", "both"] as const) {
      const caps = remoteConnectionCapabilities(mode);
      expect(Object.keys(caps).sort()).toEqual(["webrtc", "websocketData"]);
      expect(caps).not.toHaveProperty("signaling");
      expect(caps).not.toHaveProperty("websocket");
    }
  });
});

describe("remote_connections_is_independent_of_legacy_relay_env", () => {
  /** Every legacy relay / cockpit-relay env key from server + relay packages. */
  const legacyAssignments: Record<string, string> = {
    COCKPIT_RELAY_ID: "relay-x",
    COCKPIT_RELAY_URL: "wss://relay.example.com/ws",
    RELAY_CONTROL_SECRET: "x".repeat(32),
    RELAY_CA_PUBLIC_KEYS: "pk1",
    RELAY_REVOKED_IDS: "revoked",
    RELAY_PORT: "3010",
    PORT: "3010",
    RELAY_TOKEN_ISSUER: "https://example.com",
    RELAY_JWKS_URL: "https://example.com/jwks",
    RELAY_ID: "relay-local",
    RELAY_CONTROL_INGEST_URL: "https://example.com/control",
    RELAY_MODE: "shared-secret",
    RELAY_BIND_ADDR: "127.0.0.1",
    RELAY_CERTIFICATE_PATH: "/tmp/cert.pem",
    RELAY_PRIVATE_KEY_PATH: "/tmp/key.pem",
    REDIS_URL: "redis://127.0.0.1:6379",
    RELAY_HEARTBEAT_MS: "10000",
    RELAY_LEASE_TTL_MS: "30000",
    RELAY_MAX_FRAME_BYTES: "8388608",
    RELAY_MAX_CHANNELS_PER_CLIENT: "16",
    RELAY_MAX_CONNECTIONS_PER_INSTANCE: "1",
    RELAY_CLIENT_RATE_LIMIT_PER_SECOND: "60",
    RELAY_SHUTDOWN_GRACE_MS: "10000",
    BETTER_AUTH_URL: "https://example.com",
  };

  it.each([
    "oss",
    "enterprise",
    "hosted",
    undefined,
  ] as const)("env-bag resolver depends only on REMOTE_CONNECTIONS with profile=%j and all legacy relay vars set", (profile) => {
    for (const mode of [undefined, "webrtc", "websocket", "both"] as const) {
      const bag: Record<string, string | undefined> = {
        ...legacyAssignments,
        DEPLOYMENT_PROFILE: profile,
        REMOTE_CONNECTIONS: mode,
      };
      // Flip every legacy key individually to a distinct noise value; mode must hold.
      for (const key of Object.keys(legacyAssignments)) {
        const noisy = { ...bag, [key]: `noise-${key}` };
        expect(remoteConnectionsFromEnvBag(noisy)).toBe(mode ?? "both");
      }
      expect(remoteConnectionsFromEnvBag(bag)).toBe(mode ?? "both");
    }
  });

  it("server.ts schema only transforms REMOTE_CONNECTIONS via parseRemoteConnectionsMode", async () => {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    const dir = path.dirname(new URL(import.meta.url).pathname);
    const serverSrc = await fs.readFile(path.join(dir, "server.ts"), "utf8");
    const blockMatch = serverSrc.match(
      /REMOTE_CONNECTIONS:\s*z[\s\S]*?RELAY_REVOKED_IDS|REMOTE_CONNECTIONS:\s*z[\s\S]*?},\s*runtimeEnv/,
    );
    // Narrower: the transform body must call parseRemoteConnectionsMode(value).
    expect(serverSrc).toMatch(
      /REMOTE_CONNECTIONS:\s*z[\s\S]{0,400}parseRemoteConnectionsMode\(\s*value\s*\)/,
    );
    // Schema field must not reference legacy relay modes.
    const remoteField = serverSrc.slice(
      serverSrc.indexOf("REMOTE_CONNECTIONS:"),
      serverSrc.indexOf("runtimeEnv:"),
    );
    expect(remoteField).not.toMatch(/RELAY_MODE|COCKPIT_RELAY|DEPLOYMENT_PROFILE/);
    expect(blockMatch || remoteField).toBeTruthy();
  });
});

describe("remote_connections_server_only_surface", () => {
  it("is not re-exported from web/native source entrypoints", async () => {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    const dir = path.dirname(new URL(import.meta.url).pathname);
    const webSrc = await fs.readFile(path.join(dir, "web.ts"), "utf8");
    const nativeSrc = await fs.readFile(path.join(dir, "native.ts"), "utf8");
    for (const src of [webSrc, nativeSrc]) {
      expect(src).not.toMatch(/REMOTE_CONNECTIONS/);
      expect(src).not.toMatch(/REMOTE_CONNECTION_CAPABILITIES/);
      expect(src).not.toMatch(/parseRemoteConnectionsMode/);
      expect(src).not.toMatch(/remote-connections/);
    }
  });

  it("freezes capability objects", () => {
    const caps = remoteConnectionCapabilities("webrtc");
    expect(Object.isFrozen(caps)).toBe(true);
    expect(() => {
      // @ts-expect-error immutability
      caps.websocketData = true;
    }).toThrow();
  });
});
