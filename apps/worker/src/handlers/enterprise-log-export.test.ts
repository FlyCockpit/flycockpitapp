import type { EnterpriseLogExportJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/api/enterprise/log-export", () => ({
  generateEnterpriseLogExport: vi.fn(),
}));

const { generateEnterpriseLogExport } = await import("@flycockpit/api/enterprise/log-export");
const { handleEnterpriseLogExportJob } = await import("./enterprise-log-export");
const generate = generateEnterpriseLogExport as unknown as ReturnType<typeof vi.fn>;

function fakeJob(data: EnterpriseLogExportJobData): Job<EnterpriseLogExportJobData> {
  return { id: "job-1", data } as Job<EnterpriseLogExportJobData>;
}

describe("handleEnterpriseLogExportJob", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("generates the requested export", async () => {
    generate.mockResolvedValue({ id: "export-1", status: "READY" });

    await expect(handleEnterpriseLogExportJob(fakeJob({ exportId: "export-1" }))).resolves.toEqual({
      exportId: "export-1",
      status: "READY",
    });
    expect(generate).toHaveBeenCalledWith("export-1");
  });
});
