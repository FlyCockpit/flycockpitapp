import type { EchoJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock @flycockpit/db before importing the handler
vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});

// Re-import the mocked module so we can configure return values
const { default: prisma } = await import("@flycockpit/db");

// Type-safe handle to the mocked Prisma methods
const db = prisma as unknown as {
  appSetting: {
    upsert: MockInstance;
  };
};

/** Build a minimal fake BullMQ Job object for testing. */
function fakeJob(overrides?: Partial<Job<EchoJobData>>): Job<EchoJobData> {
  return {
    id: "test-job-1",
    data: { message: "hello world" },
    ...overrides,
  } as Job<EchoJobData>;
}

describe("handleEchoJob", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("persists the echo message as an AppSetting", async () => {
    const { handleEchoJob } = await import("./echo.js");

    db.appSetting.upsert.mockResolvedValue({
      key: "echo:test-job-1",
      value: "hello world",
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const job = fakeJob();
    const result = await handleEchoJob(job);

    expect(result).toEqual({ echoed: "hello world" });
    expect(db.appSetting.upsert).toHaveBeenCalledOnce();
    expect(db.appSetting.upsert).toHaveBeenCalledWith({
      where: { key: "echo:test-job-1" },
      update: { value: "hello world" },
      create: { key: "echo:test-job-1", value: "hello world" },
    });
  });

  it("uses the job ID to build the setting key", async () => {
    const { handleEchoJob } = await import("./echo.js");

    db.appSetting.upsert.mockResolvedValue({
      key: "echo:custom-id",
      value: "custom message",
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const job = fakeJob({ id: "custom-id", data: { message: "custom message" } });
    await handleEchoJob(job);

    expect(db.appSetting.upsert).toHaveBeenCalledWith({
      where: { key: "echo:custom-id" },
      update: { value: "custom message" },
      create: { key: "echo:custom-id", value: "custom message" },
    });
  });

  it("propagates Prisma errors to the caller", async () => {
    const { handleEchoJob } = await import("./echo.js");

    db.appSetting.upsert.mockRejectedValue(new Error("DB connection lost"));

    const job = fakeJob();

    await expect(handleEchoJob(job)).rejects.toThrow("DB connection lost");
  });
});
