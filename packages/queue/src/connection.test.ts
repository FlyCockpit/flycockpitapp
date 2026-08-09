import { afterEach, describe, expect, it, vi } from "vitest";

const { redisConstructor } = vi.hoisted(() => ({
  redisConstructor: vi.fn(() => ({ quit: vi.fn(), disconnect: vi.fn() })),
}));
vi.mock("ioredis", () => ({ default: redisConstructor }));
vi.mock("@flycockpit/env/shared", () => ({ env: { REDIS_URL: "redis://127.0.0.1:6379" } }));

describe("Redis connection lifecycle", () => {
  afterEach(() => vi.resetModules());
  it("redis_factory_import_opens_no_socket", async () => {
    const connection = await import("./connection");
    expect(redisConstructor).not.toHaveBeenCalled();
    connection.getRedisConnection();
    expect(redisConstructor).toHaveBeenCalledTimes(1);
    connection.resetRedisConnectionForTests();
  });
});
