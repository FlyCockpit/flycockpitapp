import { describe, expect, it } from "vitest";
import { verifyServerEligibility } from "./server-eligibility";

function profileFetch(body: unknown) {
  return async () => new Response(JSON.stringify(body), { status: 200 });
}

describe("native server eligibility", () => {
  it("allows hosted servers that advertise native eligibility", async () => {
    const result = await verifyServerEligibility(
      "https://app.flycockpit.test/path?ignored=1",
      profileFetch({
        profile: "hosted",
        productName: "Flycockpit",
        version: "dev",
        nativeAppEligible: true,
      }),
    );
    expect(result.status).toBe("eligible");
    if (result.status === "eligible") expect(result.serverUrl).toBe("https://app.flycockpit.test");
  });

  it("allows enterprise servers with a valid native-capable license", async () => {
    const result = await verifyServerEligibility(
      "enterprise.flycockpit.test",
      profileFetch({
        profile: "enterprise",
        productName: "Flycockpit Enterprise",
        version: "1.2.3",
        nativeAppEligible: true,
        enterpriseLicense: { org: "Acme", expiresAt: "2029-01-01T00:00:00.000Z", valid: true },
      }),
    );
    expect(result.status).toBe("eligible");
  });

  it("refuses enterprise servers with missing or tampered license eligibility", async () => {
    const result = await verifyServerEligibility(
      "https://enterprise.flycockpit.test",
      profileFetch({
        profile: "enterprise",
        productName: "Flycockpit Enterprise",
        version: "1.2.3",
        nativeAppEligible: false,
        enterpriseLicense: { org: "Acme", expiresAt: "2029-01-01T00:00:00.000Z", valid: false },
      }),
    );
    expect(result.status).toBe("enterprise_invalid");
  });

  it("refuses OSS self-hosted servers", async () => {
    const result = await verifyServerEligibility(
      "http://localhost:3000",
      profileFetch({
        profile: "oss",
        productName: "Flycockpit",
        version: "dev",
        nativeAppEligible: false,
      }),
    );
    expect(result.status).toBe("oss_refused");
  });
});
