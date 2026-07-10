import { env } from "@flycockpit/env/server";
import { ORPCError } from "@orpc/server";
import { getMissingRelayControlConfigKeys, getRelayControlConfig } from "./relay-config";

function webSocketUrlFromControlUrl(controlUrl: string) {
  const url = new URL(controlUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/ws";
  url.search = "";
  url.hash = "";
  return url.toString();
}

export function defaultRelayUrl() {
  const config = getRelayControlConfig();
  if (config) return webSocketUrlFromControlUrl(config.controlUrl);
  if (env.COCKPIT_RELAY_URL) return env.COCKPIT_RELAY_URL;

  const base = new URL(env.BETTER_AUTH_URL);
  base.protocol = base.protocol === "https:" ? "wss:" : "ws:";
  base.pathname = "/ws";
  base.search = "";
  base.hash = "";
  return base.toString();
}

export function requireConfiguredRelayForMint() {
  const config = getRelayControlConfig();
  if (!config) {
    const missing = getMissingRelayControlConfigKeys();
    throw new ORPCError("SERVICE_UNAVAILABLE", {
      message: `Relay is not configured. Missing ${missing.join(", ") || "relay control config"}.`,
    });
  }
  return { relayId: config.relayId, relayUrl: defaultRelayUrl() };
}
