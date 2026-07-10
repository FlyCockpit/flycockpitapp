import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  attentionNotificationPayloadSchema,
  clientRelayFrameSchema,
  daemonClientRelayFrameSchema,
  daemonControlRelayFrameSchema,
  daemonRelayFrameSchema,
  relayControlMessageSchema,
  stampedClientRelayFrameSchema,
  systemRelayFrameSchema,
  userNotificationRelayFrameSchema,
  userPresenceRelayFrameSchema,
} from "./envelopes";

type Schema = z.ZodType<unknown>;

const fixturesRoot = join(import.meta.dirname, "../fixtures");

const validFixtures = {
  "client-relay-frame.json": clientRelayFrameSchema,
  "stamped-client-relay-frame.json": stampedClientRelayFrameSchema,
  "daemon-client-relay-frame.json": daemonClientRelayFrameSchema,
  "daemon-control-relay-frame.json": daemonControlRelayFrameSchema,
  "user-presence-relay-frame.json": userPresenceRelayFrameSchema,
  "user-notification-relay-frame.json": userNotificationRelayFrameSchema,
  "system-relay-frame.json": systemRelayFrameSchema,
  "control-disconnect-instance.json": relayControlMessageSchema,
  "control-disconnect-user.json": relayControlMessageSchema,
  "control-notify-user.json": relayControlMessageSchema,
} satisfies Record<string, Schema>;

type ValidFixtureName = keyof typeof validFixtures;

const allSchemas: Schema[] = [
  clientRelayFrameSchema,
  stampedClientRelayFrameSchema,
  daemonRelayFrameSchema,
  userPresenceRelayFrameSchema,
  userNotificationRelayFrameSchema,
  systemRelayFrameSchema,
  relayControlMessageSchema,
  attentionNotificationPayloadSchema,
];

describe("relay protocol fixtures", () => {
  it("parses and round-trips every valid fixture canonically", () => {
    const names = readdirSync(fixturesRoot).filter((name) => name.endsWith(".json"));
    expect(names.sort()).toEqual(Object.keys(validFixtures).sort());

    for (const name of names) {
      expect(isValidFixtureName(name), name).toBe(true);
      if (!isValidFixtureName(name)) continue;

      const raw = readJson(name);
      const parsed = validFixtures[name].parse(raw);
      expect(stableJson(parsed), name).toBe(stableJson(raw));
      if (name === "daemon-control-relay-frame.json") {
        const payload = z
          .object({ payload: attentionNotificationPayloadSchema })
          .parse(raw).payload;
        expect(stableJson(payload), `${name} payload`).toBe(
          stableJson((raw as { payload: unknown }).payload),
        );
      }
    }
  });

  it("rejects every invalid fixture with every schema", () => {
    const invalidRoot = join(fixturesRoot, "invalid");
    const names = readdirSync(invalidRoot).filter((name) => name.endsWith(".json"));
    expect(names.length).toBeGreaterThanOrEqual(5);

    for (const name of names) {
      const raw = JSON.parse(readFileSync(join(invalidRoot, name), "utf8")) as unknown;
      for (const schema of allSchemas) {
        expect(schema.safeParse(raw).success, `${name} parsed unexpectedly`).toBe(false);
      }
    }
  });
});

function isValidFixtureName(name: string): name is ValidFixtureName {
  return name in validFixtures;
}

function readJson(name: string) {
  return JSON.parse(readFileSync(join(fixturesRoot, name), "utf8")) as unknown;
}

function stableJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => [key, sortKeys(child)]),
  );
}
