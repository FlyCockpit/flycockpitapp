import { createSign, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/env/server", () => ({
  env: {
    DEPLOYMENT_PROFILE: "oss",
    PRODUCT_NAME: "Flycockpit",
    ENTERPRISE_LICENSE_FILE: undefined,
    ENTERPRISE_LICENSE_PUBLIC_KEY: undefined,
  },
}));

const { env } = await import("@flycockpit/env/server");
const {
  enterpriseLicenseSchema,
  getEnterpriseLicenseStatus,
  getPublicDeploymentProfile,
  verifyEnterpriseLicenseSignature,
} = await import("./deployment-profile");
const mutableEnv = env as unknown as {
  DEPLOYMENT_PROFILE: "hosted" | "enterprise" | "oss";
  PRODUCT_NAME: string;
  ENTERPRISE_LICENSE_FILE?: string;
  ENTERPRISE_LICENSE_PUBLIC_KEY?: string;
};

type UnsignedLicense = {
  org: string;
  expiresAt: string;
  entitlements: {
    nativeAppAccess?: boolean;
    maxInstances?: number;
    sharingEnabled?: boolean;
    logExport?: boolean;
  };
};

function signLicense(license: UnsignedLicense, privateKey: string) {
  const canonical = JSON.stringify({
    entitlements: Object.fromEntries(
      Object.entries(license.entitlements).sort(([a], [b]) => a.localeCompare(b)),
    ),
    expiresAt: license.expiresAt,
    org: license.org,
  });
  const signer = createSign("RSA-SHA256");
  signer.update(canonical);
  signer.end();
  return signer.sign(privateKey, "base64");
}

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

function signedLicense(unsigned: UnsignedLicense, privateKey: string) {
  return enterpriseLicenseSchema.parse({
    ...unsigned,
    signature: signLicense(unsigned, privateKey),
  });
}

let tempDir: string | null = null;

describe("deployment profiles", () => {
  beforeEach(() => {
    mutableEnv.DEPLOYMENT_PROFILE = "oss";
    mutableEnv.PRODUCT_NAME = "Flycockpit";
    mutableEnv.ENTERPRISE_LICENSE_FILE = undefined;
    mutableEnv.ENTERPRISE_LICENSE_PUBLIC_KEY = undefined;
  });

  afterEach(() => {
    if (tempDir) rmSync(tempDir, { recursive: true, force: true });
    tempDir = null;
    vi.unstubAllEnvs();
  });

  it("accepts a valid signed license and rejects tampering", () => {
    const { publicPem, privatePem } = keyPair();
    const unsigned = {
      org: "Acme Corp",
      expiresAt: "2030-01-01T00:00:00.000Z",
      entitlements: {
        nativeAppAccess: true,
        maxInstances: 50,
        sharingEnabled: true,
        logExport: true,
      },
    };
    const license = signedLicense(unsigned, privatePem);

    expect(verifyEnterpriseLicenseSignature(license, publicPem)).toBe(true);
    expect(verifyEnterpriseLicenseSignature({ ...license, org: "Other Corp" }, publicPem)).toBe(
      false,
    );
  });

  it("marks expired enterprise licenses invalid without failing signature verification", () => {
    const { publicPem, privatePem } = keyPair();
    tempDir = mkdtempSync(join(tmpdir(), "flycockpit-license-"));
    const license = signedLicense(
      {
        org: "Acme Corp",
        expiresAt: "2025-01-01T00:00:00.000Z",
        entitlements: { nativeAppAccess: true, maxInstances: 50 },
      },
      privatePem,
    );
    const licenseFile = join(tempDir, "license.json");
    writeFileSync(licenseFile, JSON.stringify(license));
    mutableEnv.DEPLOYMENT_PROFILE = "enterprise";
    mutableEnv.ENTERPRISE_LICENSE_FILE = licenseFile;
    mutableEnv.ENTERPRISE_LICENSE_PUBLIC_KEY = publicPem;

    const status = getEnterpriseLicenseStatus(new Date("2026-01-01T00:00:00.000Z"));

    expect(status).toMatchObject({ signatureValid: true, expired: true, valid: false });
  });

  it("returns the public descriptor for OSS and hosted profiles", () => {
    expect(getPublicDeploymentProfile()).toMatchObject({
      profile: "oss",
      productName: "Flycockpit",
      nativeAppEligible: false,
    });

    mutableEnv.DEPLOYMENT_PROFILE = "hosted";
    mutableEnv.PRODUCT_NAME = "Flycockpit Cloud";
    vi.stubEnv("BUILD_VERSION", "test-build");

    expect(getPublicDeploymentProfile()).toEqual({
      profile: "hosted",
      productName: "Flycockpit Cloud",
      version: "test-build",
      nativeAppEligible: true,
      enterpriseLicense: undefined,
    });
  });

  it("returns non-secret enterprise license status in the public descriptor", () => {
    const { publicPem, privatePem } = keyPair();
    tempDir = mkdtempSync(join(tmpdir(), "flycockpit-license-"));
    const license = signedLicense(
      {
        org: "Acme Corp",
        expiresAt: "2030-01-01T00:00:00.000Z",
        entitlements: { nativeAppAccess: true, maxInstances: 50 },
      },
      privatePem,
    );
    const licenseFile = join(tempDir, "license.json");
    writeFileSync(licenseFile, JSON.stringify(license));
    mutableEnv.DEPLOYMENT_PROFILE = "enterprise";
    mutableEnv.ENTERPRISE_LICENSE_FILE = licenseFile;
    mutableEnv.ENTERPRISE_LICENSE_PUBLIC_KEY = publicPem;

    const descriptor = getPublicDeploymentProfile();

    expect(descriptor).toMatchObject({
      profile: "enterprise",
      nativeAppEligible: true,
      enterpriseLicense: { org: "Acme Corp", valid: true },
    });
    expect(JSON.stringify(descriptor)).not.toContain(license.signature);
  });
});
