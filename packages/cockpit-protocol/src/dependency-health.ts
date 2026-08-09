import { z } from "zod";

export const DEPENDENCY_HEALTH_SCHEMA_VERSION = 1 as const;

export type DependencyHealthState =
  | "pending"
  | "available"
  | "missing"
  | "incompatible"
  | "timed_out"
  | "failed"
  | "unknown"
  | "not_applicable";

export interface DependencyHealthRow {
  id: string;
  state: DependencyHealthState;
  importance:
    | "required_for_default_safety"
    | "required_when_feature_selected"
    | "optional_integration"
    | "optional_accelerator";
  target: "host" | "container";
  required_version?: string;
  discovered_version?: string;
  cause?: { kind: string } & Record<string, unknown>;
  remedy?: { kind: string } & Record<string, unknown>;
  reason: string;
}

export interface DependencyHealthSnapshotV1 {
  schema_version: typeof DEPENDENCY_HEALTH_SCHEMA_VERSION;
  generation: number;
  platform:
    | "mac_os"
    | "windows"
    | "debian_ubuntu"
    | "fedora_rhel"
    | "arch"
    | "generic_linux"
    | "other_unix"
    | "unsupported";
  rows: DependencyHealthRow[];
}

export const DependencyHealthSnapshotV1Schema = z.object({
  schema_version: z.literal(DEPENDENCY_HEALTH_SCHEMA_VERSION),
  generation: z.number().int().nonnegative(),
  platform: z.enum([
    "mac_os",
    "windows",
    "debian_ubuntu",
    "fedora_rhel",
    "arch",
    "generic_linux",
    "other_unix",
    "unsupported",
  ]),
  rows: z.array(
    z.object({
      id: z.string(),
      state: z.enum([
        "pending",
        "available",
        "missing",
        "incompatible",
        "timed_out",
        "failed",
        "unknown",
        "not_applicable",
      ]),
      importance: z.enum([
        "required_for_default_safety",
        "required_when_feature_selected",
        "optional_integration",
        "optional_accelerator",
      ]),
      target: z.enum(["host", "container"]),
      required_version: z.string().optional(),
      discovered_version: z.string().optional(),
      cause: z.object({ kind: z.string() }).passthrough().optional(),
      remedy: z.object({ kind: z.string() }).passthrough().optional(),
      reason: z.string(),
    }),
  ),
});
