import type { SeedJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock @flycockpit/db/seed before importing the handler. The handler must not
// touch a real database in CI — it only orchestrates runSeed().
const runSeedMock = vi.fn();
vi.mock("@flycockpit/db/seed", () => ({
  runSeed: () => runSeedMock(),
}));

/** Build a minimal fake BullMQ Job object for testing. */
function fakeJob(overrides?: Partial<Job<SeedJobData>>): Job<SeedJobData> {
  return {
    id: "seed-job-1",
    data: { requestedBy: "admin-user-id" },
    ...overrides,
  } as Job<SeedJobData>;
}

describe("handleSeedJob", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns the seed summary plus a measured durationMs", async () => {
    const { handleSeedJob } = await import("./seed.js");
    runSeedMock.mockResolvedValue({ summary: ["Ensured admin user", "Seeded 3 posts"] });

    const result = await handleSeedJob(fakeJob());

    expect(runSeedMock).toHaveBeenCalledOnce();
    expect(result.summary).toEqual(["Ensured admin user", "Seeded 3 posts"]);
    expect(typeof result.durationMs).toBe("number");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("handles an empty seed (stub) without error", async () => {
    const { handleSeedJob } = await import("./seed.js");
    runSeedMock.mockResolvedValue({ summary: [] });

    const result = await handleSeedJob(fakeJob());

    expect(result.summary).toEqual([]);
  });

  it("propagates seed failures to the caller (so the job is marked failed)", async () => {
    const { handleSeedJob } = await import("./seed.js");
    runSeedMock.mockRejectedValue(new Error("unique constraint violation"));

    await expect(handleSeedJob(fakeJob())).rejects.toThrow("unique constraint violation");
  });
});
