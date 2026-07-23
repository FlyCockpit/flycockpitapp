import { z } from "zod";

export const RELAY_ENVELOPE_VERSION = 1 as const;

export const relayGrantScopeSchema = z.enum([
  "terminal",
  "agent",
  "agent_readonly",
  "project_files",
]);
export type RelayGrantScope = z.infer<typeof relayGrantScopeSchema>;

export const relayGrantSchema = z
  .object({
    scope: relayGrantScopeSchema,
    projectRoot: z.string().min(1).max(4096).nullable(),
  })
  .strict();
export type RelayGrant = z.infer<typeof relayGrantSchema>;

export const relayPrincipalSchema = z
  .object({
    userId: z.string().min(1),
    grants: z.array(relayGrantSchema),
  })
  .strict();
export type RelayPrincipal = z.infer<typeof relayPrincipalSchema>;

export const channelIdSchema = z.string().trim().min(1).max(128);
export const relayClientIdSchema = z.string().trim().min(1).max(128);

export const attentionEventTypeSchema = z.enum([
  "APPROVAL_NEEDED",
  "QUESTION_RAISED",
  "TURN_DONE",
  "TURN_ERROR",
  "SCHEDULE_DONE",
]);
export type AttentionEventType = z.infer<typeof attentionEventTypeSchema>;

export const attentionNotificationPayloadSchema = z
  .object({
    eventId: z.string().trim().min(1).max(128),
    sessionId: z.string().trim().min(1).max(256),
    projectRoot: z.string().trim().min(1).max(4096).nullable().optional(),
    eventType: attentionEventTypeSchema,
    fixedStringTitle: z.string().trim().min(1).max(160),
    fixedStringBody: z.string().trim().max(240).nullable().optional(),
    ts: z.string().datetime(),
    targetPrincipal: z
      .object({ userId: z.string().trim().min(1).max(128) })
      .strict()
      .nullable()
      .optional(),
  })
  .strict();
export type AttentionNotificationPayload = z.infer<typeof attentionNotificationPayloadSchema>;

export const userPresenceRelayFrameSchema = z
  .object({
    v: z.literal(RELAY_ENVELOPE_VERSION),
    type: z.literal("presence"),
    clientId: relayClientIdSchema,
    visible: z.boolean(),
    ts: z.string().datetime().optional(),
  })
  .strict();
export type UserPresenceRelayFrame = z.infer<typeof userPresenceRelayFrameSchema>;

export const userRelayFrameSchema = userPresenceRelayFrameSchema;
export type UserRelayFrame = z.infer<typeof userRelayFrameSchema>;

export const userNotificationRelayFrameSchema = z
  .object({
    v: z.literal(RELAY_ENVELOPE_VERSION),
    type: z.literal("notification"),
    notification: z
      .object({
        id: z.string().min(1),
        type: attentionEventTypeSchema,
        title: z.string().min(1).max(160),
        body: z.string().max(240).nullable().optional(),
        url: z.string().min(1).max(4096),
        instanceId: z.string().min(1),
        sessionRef: z.string().min(1).max(256).nullable().optional(),
        createdAt: z.string().datetime(),
      })
      .strict(),
  })
  .strict();
export type UserNotificationRelayFrame = z.infer<typeof userNotificationRelayFrameSchema>;

export const clientRelayFrameSchema = z
  .object({
    v: z.literal(RELAY_ENVELOPE_VERSION),
    channelId: channelIdSchema,
    payload: z.unknown(),
  })
  .strict();
export type ClientRelayFrame = z.infer<typeof clientRelayFrameSchema>;

export const stampedClientRelayFrameSchema = z
  .object({
    v: z.literal(RELAY_ENVELOPE_VERSION),
    channelId: channelIdSchema,
    from: z.literal("client"),
    principal: relayPrincipalSchema,
    payload: z.unknown(),
  })
  .strict();
export type StampedClientRelayFrame = z.infer<typeof stampedClientRelayFrameSchema>;

export const daemonClientRelayFrameSchema = z
  .object({
    v: z.literal(RELAY_ENVELOPE_VERSION),
    channelId: channelIdSchema,
    payload: z.unknown(),
  })
  .strict();
export type DaemonClientRelayFrame = z.infer<typeof daemonClientRelayFrameSchema>;

export const daemonControlRelayFrameSchema = z
  .object({
    v: z.literal(RELAY_ENVELOPE_VERSION),
    to: z.literal("control"),
    event: z.string().trim().min(1).max(128).optional(),
    payload: z.unknown(),
  })
  .strict();
export type DaemonControlRelayFrame = z.infer<typeof daemonControlRelayFrameSchema>;

export const daemonRelayFrameSchema = z.union([
  daemonClientRelayFrameSchema,
  daemonControlRelayFrameSchema,
]);
export type DaemonRelayFrame = z.infer<typeof daemonRelayFrameSchema>;

export const systemRelayFrameSchema = z
  .object({
    v: z.literal(RELAY_ENVELOPE_VERSION),
    type: z.literal("system"),
    code: z.enum([
      "bad_frame",
      "channel_limit",
      "daemon_replaced",
      "forced_disconnect",
      "instance_offline",
      "rate_limited",
    ]),
  })
  .strict();
export type SystemRelayFrame = z.infer<typeof systemRelayFrameSchema>;

export const relayControlMessageSchema = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("disconnect_instance"),
      instanceId: z.string().min(1),
      reason: z.string().min(1).max(200).optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("disconnect_user"),
      userId: z.string().min(1),
      instanceId: z.string().min(1).optional(),
      reason: z.string().min(1).max(200).optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("notify_user"),
      userId: z.string().min(1),
      notification: userNotificationRelayFrameSchema.shape.notification,
    })
    .strict(),
]);
export type RelayControlMessage = z.infer<typeof relayControlMessageSchema>;
