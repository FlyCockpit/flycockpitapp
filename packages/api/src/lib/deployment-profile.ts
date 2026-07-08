import { createVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { env } from "@flycockpit/env/server";
import { z } from "zod";

export const deploymentProfileSchema = z.enum(["hosted", "enterprise", "oss"]);
export type DeploymentProfile = z.infer<typeof deploymentProfileSchema>;

const entitlementsSchema = z.object({
  nativeAppAccess: z.boolean().optional(),
  maxInstances: z.number().int().nonnegative().optional(),
  sharingEnabled: z.boolean().optional(),
  logExport: z.boolean().optional(),
});

export const enterpriseLicenseSchema = z.object({
  org: z.string().min(1),
  expiresAt: z.string().datetime(),
  entitlements: entitlementsSchema.default({}),
  signature: z.string().min(1),
});

export type EnterpriseLicense = z.infer<typeof enterpriseLicenseSchema>;

function canonicalLicensePayload(license: Omit<EnterpriseLicense, "signature">) {
  return JSON.stringify({
    entitlements: Object.fromEntries(
      Object.entries(license.entitlements).sort(([a], [b]) => a.localeCompare(b)),
    ),
    expiresAt: license.expiresAt,
    org: license.org,
  });
}

export function verifyEnterpriseLicenseSignature(
  license: EnterpriseLicense,
  publicKeyPem: string,
): boolean {
  const verifier = createVerify("RSA-SHA256");
  const { signature, ...payload } = license;
  verifier.update(canonicalLicensePayload(payload));
  verifier.end();
  return verifier.verify(publicKeyPem, signature, "base64");
}

export function parseEnterpriseLicense(raw: string): EnterpriseLicense {
  return enterpriseLicenseSchema.parse(JSON.parse(raw));
}

export function loadEnterpriseLicense(): EnterpriseLicense | null {
  if (!env.ENTERPRISE_LICENSE_FILE) return null;
  return parseEnterpriseLicense(readFileSync(env.ENTERPRISE_LICENSE_FILE, "utf8"));
}

export function getEnterpriseLicenseStatus(now = new Date()) {
  if (env.DEPLOYMENT_PROFILE !== "enterprise") return null;
  const license = loadEnterpriseLicense();
  if (!license || !env.ENTERPRISE_LICENSE_PUBLIC_KEY) return null;
  const signatureValid = verifyEnterpriseLicenseSignature(
    license,
    env.ENTERPRISE_LICENSE_PUBLIC_KEY,
  );
  const expiresAt = new Date(license.expiresAt);
  return {
    org: license.org,
    expiresAt,
    entitlements: license.entitlements,
    valid: signatureValid && expiresAt > now,
    signatureValid,
    expired: expiresAt <= now,
  };
}

export function getPublicDeploymentProfile() {
  const enterpriseLicense = getEnterpriseLicenseStatus();
  const profile = env.DEPLOYMENT_PROFILE;
  return {
    profile,
    productName: env.PRODUCT_NAME,
    version: process.env.BUILD_VERSION || "dev",
    nativeAppEligible:
      profile === "hosted" || (profile === "enterprise" && enterpriseLicense?.valid === true),
    enterpriseLicense: enterpriseLicense
      ? {
          org: enterpriseLicense.org,
          expiresAt: enterpriseLicense.expiresAt,
          valid: enterpriseLicense.valid,
        }
      : undefined,
  };
}
