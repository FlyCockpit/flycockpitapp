import { z } from "zod";

/**
 * Server-only remote data-transport capability ceiling.
 * Signaling over the main-app WebSocket is always required and is not
 * represented by these capability booleans.
 */
export const REMOTE_CONNECTION_MODES = ["webrtc", "websocket", "both"] as const;

export type RemoteConnectionMode = (typeof REMOTE_CONNECTION_MODES)[number];

export type RemoteConnectionCapabilities = Readonly<{
  /** Permit direct ICE / TURN WebRTC data channels. */
  webrtc: boolean;
  /**
   * Permit the in-app E2E-encrypted WebSocket data path.
   * Named `websocketData` so callers never confuse it with signaling.
   */
  websocketData: boolean;
}>;

/** Zod schema for the raw env value. Empty/omitted is handled separately. */
export const remoteConnectionsModeSchema = z.enum(REMOTE_CONNECTION_MODES);

/**
 * Parse `REMOTE_CONNECTIONS` with the prompt contract:
 * - omitted or empty → `both`
 * - whitespace-only / unknown / aliases / case variants → fail
 * - only exact `webrtc` | `websocket` | `both`
 */
export function parseRemoteConnectionsMode(raw: string | undefined | null): RemoteConnectionMode {
  if (raw === undefined || raw === null || raw === "") {
    return "both";
  }
  // Whitespace-only and padded values are invalid (not defaulted).
  if (raw.trim() !== raw || raw.trim() === "") {
    throw new Error(
      `REMOTE_CONNECTIONS must be one of ${REMOTE_CONNECTION_MODES.join("|")} (got ${JSON.stringify(raw)})`,
    );
  }
  const parsed = remoteConnectionsModeSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(
      `REMOTE_CONNECTIONS must be one of ${REMOTE_CONNECTION_MODES.join("|")} (got ${JSON.stringify(raw)})`,
    );
  }
  return parsed.data;
}

/**
 * Resolve the mode from a full server env bag.
 * **Only** `REMOTE_CONNECTIONS` is read — legacy `RELAY_*` / `COCKPIT_RELAY_*`
 * and `DEPLOYMENT_PROFILE` never influence the result.
 */
export function remoteConnectionsFromEnvBag(
  bag: Readonly<Record<string, string | undefined>>,
): RemoteConnectionMode {
  return parseRemoteConnectionsMode(bag.REMOTE_CONNECTIONS);
}

/** Pure capability matrix from a validated mode. */
export function remoteConnectionCapabilities(
  mode: RemoteConnectionMode,
): RemoteConnectionCapabilities {
  switch (mode) {
    case "webrtc":
      return Object.freeze({ webrtc: true, websocketData: false });
    case "websocket":
      return Object.freeze({ webrtc: false, websocketData: true });
    case "both":
      return Object.freeze({ webrtc: true, websocketData: true });
    default: {
      const _exhaustive: never = mode;
      throw new Error(`unreachable RemoteConnectionMode: ${_exhaustive}`);
    }
  }
}
