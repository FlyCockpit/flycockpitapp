import { afterEach, describe, expect, it, vi } from "vitest";

const originalEnv = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnv };
  vi.resetModules();
});

describe("relay env", () => {
  it("requires a stable RELAY_ID at boot", async () => {
    vi.resetModules();
    process.env = {
      ...originalEnv,
      NODE_ENV: "test",
      BETTER_AUTH_URL: "https://app.example.test",
      RELAY_ID: "",
    };

    await expect(import("@flycockpit/env/relay")).rejects.toThrow("RELAY_ID");
  });
});
