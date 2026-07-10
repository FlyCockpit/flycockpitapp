import { timingSafeEqual } from "node:crypto";
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

export function verifyRelayCredential(request: Request): RelayIdentity {
  const config = getRelayControlConfig();
  if (!config) throw new RelayControlNotConfiguredError();

  const token = extractBearer(request.headers.get("authorization"));
  if (!token || !constantTimeEquals(token, config.controlSecret)) {
    throw new RelayCredentialUnauthorizedError();
  }

  return { relayId: config.relayId, mode: "embedded" };
}
