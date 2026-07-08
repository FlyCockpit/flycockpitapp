import z from "zod";

export const deploymentProfileDescriptorSchema = z.object({
  profile: z.enum(["hosted", "enterprise", "oss"]),
  productName: z.string().min(1),
  version: z.string().min(1),
  nativeAppEligible: z.boolean(),
  enterpriseLicense: z
    .object({
      org: z.string().min(1),
      expiresAt: z.coerce.date(),
      valid: z.boolean(),
    })
    .optional(),
});

export type DeploymentProfileDescriptor = z.infer<typeof deploymentProfileDescriptorSchema>;

export type ServerEligibilityResult =
  | { status: "eligible"; serverUrl: string; descriptor: DeploymentProfileDescriptor }
  | { status: "oss_refused"; serverUrl: string; descriptor: DeploymentProfileDescriptor }
  | { status: "enterprise_invalid"; serverUrl: string; descriptor: DeploymentProfileDescriptor }
  | { status: "invalid_url"; message: string }
  | { status: "unreachable"; serverUrl: string; message: string };

export function normalizeServerUrl(value: string) {
  const trimmed = value.trim();
  const url = new URL(trimmed.includes("://") ? trimmed : "https://" + trimmed);
  url.pathname = "";
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

export async function verifyServerEligibility(
  value: string,
  fetcher: typeof fetch = fetch,
): Promise<ServerEligibilityResult> {
  let serverUrl: string;
  try {
    serverUrl = normalizeServerUrl(value);
  } catch (error) {
    return {
      status: "invalid_url",
      message: error instanceof Error ? error.message : "Invalid URL",
    };
  }

  try {
    const response = await fetcher(serverUrl + "/api/meta/profile", {
      headers: { accept: "application/json" },
    });
    if (!response.ok) {
      return { status: "unreachable", serverUrl, message: "Server profile could not be loaded." };
    }
    const descriptor = deploymentProfileDescriptorSchema.parse(await response.json());
    if (descriptor.profile === "oss") return { status: "oss_refused", serverUrl, descriptor };
    if (descriptor.profile === "enterprise" && descriptor.nativeAppEligible !== true) {
      return { status: "enterprise_invalid", serverUrl, descriptor };
    }
    if (descriptor.nativeAppEligible !== true) {
      return { status: "enterprise_invalid", serverUrl, descriptor };
    }
    return { status: "eligible", serverUrl, descriptor };
  } catch (error) {
    return {
      status: "unreachable",
      serverUrl,
      message: error instanceof Error ? error.message : "Server profile could not be loaded.",
    };
  }
}
