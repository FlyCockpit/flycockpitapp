import { env } from "@flycockpit/env/server";

export type RelayControlConfig = {
  relayId: string;
  controlSecret: string;
  controlUrl: string;
};

let relayControlConfigOverride: RelayControlConfig | null | undefined;

function controlUrlFromWebSocketUrl(relayUrl: string) {
  const url = new URL(relayUrl);
  url.protocol = url.protocol === "wss:" ? "https:" : "http:";
  url.pathname = "/control";
  url.search = "";
  url.hash = "";
  return url.toString();
}

export function setRelayControlConfig(config: RelayControlConfig | null) {
  relayControlConfigOverride = config;
}

export function resetRelayControlConfig() {
  relayControlConfigOverride = undefined;
}

export function getMissingRelayControlConfigKeys() {
  if (relayControlConfigOverride !== undefined) {
    return relayControlConfigOverride
      ? []
      : ["COCKPIT_RELAY_ID", "COCKPIT_RELAY_URL", "RELAY_CONTROL_SECRET"];
  }

  const missing: string[] = [];
  if (!env.COCKPIT_RELAY_ID) missing.push("COCKPIT_RELAY_ID");
  if (!env.COCKPIT_RELAY_URL) missing.push("COCKPIT_RELAY_URL");
  if (!env.RELAY_CONTROL_SECRET) missing.push("RELAY_CONTROL_SECRET");
  return missing;
}

export function getRelayControlConfig(): RelayControlConfig | null {
  if (relayControlConfigOverride !== undefined) return relayControlConfigOverride;
  if (!env.COCKPIT_RELAY_ID || !env.COCKPIT_RELAY_URL || !env.RELAY_CONTROL_SECRET) return null;

  return {
    relayId: env.COCKPIT_RELAY_ID,
    controlSecret: env.RELAY_CONTROL_SECRET,
    controlUrl: controlUrlFromWebSocketUrl(env.COCKPIT_RELAY_URL),
  };
}

export function relayControlUrl() {
  return getRelayControlConfig()?.controlUrl ?? null;
}
