import { z } from "zod";

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ]),
);

export const enterpriseEventKindSchema = z.enum([
  "SESSION",
  "MESSAGE",
  "TOOL_CALL",
  "TOOL_RESULT",
  "INFERENCE",
  "TRUNCATION",
]);

export const enterpriseLogExportFormatSchema = z.enum(["RAW_NDJSON", "CHAT_JSONL"]);

export const enterpriseLogEventInputSchema = z.object({
  seq: z.number().int().nonnegative(),
  sessionId: z.string().min(1).max(200),
  kind: enterpriseEventKindSchema,
  occurredAt: z.string().datetime().optional(),
  projectRoot: z.string().trim().max(1000).optional(),
  model: z.string().trim().max(200).optional(),
  role: z.string().trim().max(40).optional(),
  content: z.string().max(200_000).optional(),
  payload: z.record(z.string(), jsonValueSchema).default({}),
  redactionVersion: z
    .string()
    .trim()
    .min(1)
    .max(80)
    .refine((value) => !/^(none|disabled|bypass)$/i.test(value), {
      message: "redactionVersion must identify the source-side redaction floor",
    }),
  truncated: z.boolean().default(false),
});

export const enterpriseIngestInputSchema = z.object({
  instanceId: z.string().min(1),
  instanceToken: z.string().min(1),
  schemaVersion: z.number().int().min(1).default(1),
  idempotencyKey: z.string().trim().max(200).optional(),
  events: z.array(enterpriseLogEventInputSchema).min(1).max(500),
});

export const enterprisePolicyUpdateInputSchema = z.object({
  orgId: z.string().min(1),
  logSyncMandated: z.boolean(),
  syncSessionEvents: z.boolean(),
  syncMessageEvents: z.boolean(),
  syncToolCallEvents: z.boolean(),
  syncInferenceEvents: z.boolean(),
  syncTruncationEvents: z.boolean(),
  includeLocalModels: z.boolean(),
  backfill: z.boolean(),
  backlogPolicy: z.enum(["since_join", "since_policy", "all_available"]),
  retentionDays: z.number().int().min(1).max(3650),
});

export const enterpriseExportFiltersSchema = z.object({
  orgId: z.string().min(1),
  dateFrom: z.string().datetime().optional(),
  dateTo: z.string().datetime().optional(),
  userIds: z.array(z.string().min(1)).max(100).optional(),
  instanceIds: z.array(z.string().min(1)).max(100).optional(),
  projectRoots: z.array(z.string().min(1).max(1000)).max(100).optional(),
  eventKinds: z.array(enterpriseEventKindSchema).max(20).optional(),
});

export const createEnterpriseExportInputSchema = z.object({
  format: enterpriseLogExportFormatSchema,
  filters: enterpriseExportFiltersSchema,
});

export type EnterpriseEventKind = z.infer<typeof enterpriseEventKindSchema>;
export type EnterpriseLogEventInput = z.infer<typeof enterpriseLogEventInputSchema>;
export type EnterpriseIngestInput = z.infer<typeof enterpriseIngestInputSchema>;
export type EnterpriseExportFilters = z.infer<typeof enterpriseExportFiltersSchema>;
export type EnterpriseLogExportFormat = z.infer<typeof enterpriseLogExportFormatSchema>;

export const ALL_ENTERPRISE_EVENT_KINDS: EnterpriseEventKind[] = [
  "SESSION",
  "MESSAGE",
  "TOOL_CALL",
  "TOOL_RESULT",
  "INFERENCE",
  "TRUNCATION",
];
