import { timingSafeEqual } from "node:crypto";
import { env } from "@flycockpit/env/server";
import { getRelayControlConfig } from "./relay-config";

export type RelayIdentity = { relayId: string; mode: "embedded" | "fleet" };

export class RelayControlNotConfiguredError extends Error {
  constructor() {
    super("Relay control is not configured.");
    this.name = "RelayControlNotConfiguredError";
  }
}

export class RelayCredentialUnauthorizedError extends Error {
  constructor() {
    super("Relay credential is invalid.");
    this.name = "RelayCredentialUnauthorizedError";
  }
}

function extractBearer(header: string | null) {
  const match = /^Bearer (.+)$/.exec(header ?? "");
  return match?.[1] ?? null;
}

function constantTimeEquals(actual: string, expected: string) {
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length) return false;
  return timingSafeEqual(actualBuffer, expectedBuffer);
}

export async function verifyRelayCredential(request: Request): Promise<RelayIdentity> {
  const token = extractBearer(request.headers.get("authorization"));
  const config = getRelayControlConfig();

  if (config && token && constantTimeEquals(token, config.controlSecret)) {
    return { relayId: config.relayId, mode: "embedded" };
  }

  if (env.DEPLOYMENT_PROFILE !== "oss" && token) {
    const { verifyFleetSessionToken } = await import("@flycockpit/api/enterprise/relay-fleet");
    const session = await verifyFleetSessionToken(token);
    if (session) return { relayId: session.relayId, mode: "fleet" };
  }

  if (!config && env.DEPLOYMENT_PROFILE === "oss") throw new RelayControlNotConfiguredError();
  throw new RelayCredentialUnauthorizedError();
}
