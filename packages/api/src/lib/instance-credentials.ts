import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { env } from "@flycockpit/env/server";

const TOKEN_PREFIX = "fci";
const SECRET_BYTES = 32;
const PREFIX_BYTES = 8;

export type InstanceCredential = {
  token: string;
  prefix: string;
  hash: string;
};

export function createInstanceCredential(): InstanceCredential {
  const prefix = randomBytes(PREFIX_BYTES).toString("hex");
  const secret = randomBytes(SECRET_BYTES).toString("hex");
  return {
    token: [TOKEN_PREFIX, prefix, secret].join("_"),
    prefix,
    hash: hashInstanceSecret(secret),
  };
}

export function parseInstanceToken(token: string): { prefix: string; secret: string } | null {
  const parts = token.split("_");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX || !parts[1] || !parts[2]) {
    return null;
  }
  return { prefix: parts[1], secret: parts[2] };
}

export function hashInstanceSecret(secret: string): string {
  return createHmac("sha256", env.BETTER_AUTH_SECRET).update(secret).digest("hex");
}

export function verifyInstanceSecret(secret: string, expectedHash: string): boolean {
  const actual = Buffer.from(hashInstanceSecret(secret), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}
