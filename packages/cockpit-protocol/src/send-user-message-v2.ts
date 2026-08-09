export const FCM2_MAX_BYTES = 2_631_500;
export const FCM2_SCHEMA_VERSION = 2;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export type MessageAttachmentKind = "image" | "audio" | "video";
export interface MessageAttachmentIdentity {
  attachment_id: string;
  attachment_version: bigint;
  checksum: Uint8Array;
  kind: MessageAttachmentKind;
}
export interface MessageTagExpansion {
  tool: string;
  path: string;
  detail: string;
  ok: boolean;
}
export interface SendUserMessageV2 {
  client_submission_id: string;
  text: string;
  display_text: string | null;
  tag_expansions: MessageTagExpansion[];
  forced_skill: string | null;
  attachments: MessageAttachmentIdentity[];
}
export interface CanonicalSendUserMessageV2 {
  session_id: string;
  canonical_project_digest: Uint8Array;
  model_config_generation: bigint;
  canonical_model_digest: Uint8Array;
  request: SendUserMessageV2;
}
export interface MessageIngressEnvelopeV2 {
  request_id: string;
  operation_id: string;
  session_locator: string;
  request: SendUserMessageV2;
}
export interface LocalOwnerDirectSendUserMessageV2 extends MessageIngressEnvelopeV2 {
  ingress: "local_owner_direct";
}
export interface AuthenticatedRemoteOperationEnvelopeV2 extends MessageIngressEnvelopeV2 {
  ingress: "authenticated_remote";
}
export type ValidatedMessageIngressV2 =
  | (LocalOwnerDirectSendUserMessageV2 & { actor: { kind: "local_owner" } })
  | (AuthenticatedRemoteOperationEnvelopeV2 & {
      actor: { kind: "remote_device"; id: Uint8Array; generation: bigint };
    });

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function validateEnvelopeIdentities(envelope: MessageIngressEnvelopeV2) {
  if (!UUID_V7.test(envelope.request_id)) throw new Error("request_id must be UUIDv7");
  if (!UUID_V7.test(envelope.operation_id)) throw new Error("operation_id must be UUIDv7");
  if (!envelope.session_locator) throw new Error("empty session locator");
  uuid(envelope.request.client_submission_id);
  if (
    new Set([envelope.request_id, envelope.operation_id, envelope.request.client_submission_id])
      .size !== 3
  )
    throw new Error("request, operation, and submission identities must be pairwise distinct");
}
export function validateLocalOwnerDirectMessageV2(
  envelope: LocalOwnerDirectSendUserMessageV2,
): ValidatedMessageIngressV2 {
  validateEnvelopeIdentities(envelope);
  return { ...envelope, actor: { kind: "local_owner" } };
}
export function validateAuthenticatedRemoteMessageV2(
  envelope: AuthenticatedRemoteOperationEnvelopeV2,
  actor: { id: Uint8Array; generation: bigint },
): ValidatedMessageIngressV2 {
  validateEnvelopeIdentities(envelope);
  if (
    actor.id.length !== 16 ||
    !actor.id.some(Boolean) ||
    actor.generation <= 0n ||
    actor.generation > 0xffffffffffffffffn
  )
    throw new Error("invalid remote actor binding");
  return { ...envelope, actor: { kind: "remote_device", ...actor } };
}

export function validateFcm2Length(length: number) {
  if (!Number.isSafeInteger(length) || length < 0 || length > FCM2_MAX_BYTES)
    throw new Error("FCM2 exceeds maximum size");
}

function rejectUnpairedSurrogates(value: string) {
  for (let i = 0; i < value.length; i++) {
    const n = value.charCodeAt(i);
    if (n >= 0xd800 && n <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("unpaired UTF-16 surrogate");
    } else if (n >= 0xdc00 && n <= 0xdfff) throw new Error("unpaired UTF-16 surrogate");
  }
}
export function hasMessageText(value: string): boolean {
  rejectUnpairedSurrogates(value);
  for (const scalar of value) {
    const n = scalar.codePointAt(0)!;
    if (
      !(
        (n >= 0x09 && n <= 0x0d) ||
        n === 0x20 ||
        n === 0x85 ||
        n === 0xa0 ||
        n === 0x1680 ||
        (n >= 0x2000 && n <= 0x200a) ||
        n === 0x2028 ||
        n === 0x2029 ||
        n === 0x202f ||
        n === 0x205f ||
        n === 0x3000
      )
    )
      return true;
  }
  return false;
}
function bytes(value: string, max: number, name: string) {
  rejectUnpairedSurrogates(value);
  const b = encoder.encode(value);
  if (b.length > max) throw new Error(`${name} exceeds byte limit`);
  return b;
}
function boundedFieldBytes(
  value: string,
  max: number,
  emptyCode: string | null,
  tooLongCode: string,
) {
  rejectUnpairedSurrogates(value);
  const encoded = encoder.encode(value);
  if (emptyCode && encoded.length === 0) throw new Error(emptyCode);
  if (encoded.length > max) throw new Error(tooLongCode);
}
function scalars(value: string) {
  let n = 0;
  for (const _ of value) n++;
  return n;
}
function uuid(value: string) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value))
    throw new Error("UUID must use canonical lowercase hyphenated spelling");
  const hex = value.replaceAll("-", "");
  if (/^0{32}$/.test(hex)) throw new Error("invalid nonnil UUID");
  return Uint8Array.from(hex.match(/../g)!, (x) => parseInt(x, 16));
}
function uuidString(value: Uint8Array) {
  const h = Array.from(value, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
const kindCode = (k: MessageAttachmentKind) => ({ image: 1, audio: 2, video: 3 })[k];
function validate(v: CanonicalSendUserMessageV2) {
  uuid(v.session_id);
  uuid(v.request.client_submission_id);
  if (v.model_config_generation < 0n || v.model_config_generation > 0xffffffffffffffffn)
    throw new Error("model config generation exceeds u64");
  if (v.canonical_project_digest.length !== 32 || !v.canonical_project_digest.some(Boolean))
    throw new Error("invalid project digest");
  if (v.canonical_model_digest.length !== 32 || !v.canonical_model_digest.some(Boolean))
    throw new Error("invalid model digest");
  const text = bytes(v.request.text, 1048576, "text");
  if (scalars(v.request.text) > 262144) throw new Error("text exceeds scalar limit");
  if (v.request.display_text !== null) {
    bytes(v.request.display_text, 1048576, "display text");
    if (scalars(v.request.display_text) > 262144)
      throw new Error("display text exceeds scalar limit");
  }
  if (!hasMessageText(v.request.text) && v.request.attachments.length === 0)
    throw new Error("message has no content");
  if (v.request.tag_expansions.length > 64) throw new Error("too many tags");
  for (const t of v.request.tag_expansions) {
    boundedFieldBytes(t.tool, 128, "fcm2_empty_tag_tool", "fcm2_tag_tool_too_long");
    boundedFieldBytes(t.path, 4096, null, "fcm2_tag_path_too_long");
    boundedFieldBytes(t.detail, 4096, null, "fcm2_tag_detail_too_long");
  }
  if (v.request.forced_skill !== null) {
    boundedFieldBytes(
      v.request.forced_skill,
      128,
      "fcm2_empty_forced_skill",
      "fcm2_forced_skill_too_long",
    );
    if (!/^[A-Za-z0-9_-]+$/.test(v.request.forced_skill))
      throw new Error("fcm2_invalid_forced_skill");
  }
  if (v.request.attachments.length > 16) throw new Error("too many attachments");
  const ids = new Set<string>();
  for (const a of v.request.attachments) {
    uuid(a.attachment_id);
    if (a.attachment_version <= 0n || a.attachment_version > 0xffffffffffffffffn)
      throw new Error("invalid attachment version");
    if (a.checksum.length !== 32) throw new Error("invalid checksum");
    if (ids.has(a.attachment_id.toLowerCase())) throw new Error("duplicate attachment id");
    ids.add(a.attachment_id.toLowerCase());
    if (!kindCode(a.kind)) throw new Error("unknown attachment kind");
  }
  return text;
}
class Writer {
  parts: Uint8Array[] = [];
  length = 0;
  raw(v: Uint8Array) {
    const next = this.length + v.length;
    if (!Number.isSafeInteger(next) || next > FCM2_MAX_BYTES)
      throw new Error("FCM2 exceeds maximum size");
    this.parts.push(v);
    this.length = next;
  }
  u8(v: number) {
    this.raw(Uint8Array.of(v));
  }
  u16(v: number) {
    this.raw(Uint8Array.of(v >>> 8, v & 255));
  }
  u32(v: number) {
    this.raw(Uint8Array.of((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255));
  }
  u64(v: bigint) {
    if (v < 0n || v > 0xffffffffffffffffn) throw new Error("integer exceeds u64");
    const out = new Uint8Array(8);
    for (let n = 7; n >= 0; n--) out[7 - n] = Number((v >> BigInt(n * 8)) & 255n);
    this.raw(out);
  }
  text16(v: string) {
    const b = bytes(v, 65535, "string");
    this.u16(b.length);
    this.raw(b);
  }
  text32(v: string) {
    const b = bytes(v, 0xffffffff, "string");
    this.u32(b.length);
    this.raw(b);
  }
  done() {
    const out = new Uint8Array(this.length);
    let offset = 0;
    for (const part of this.parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }
}
export function encodeCanonicalSendUserMessageV2(v: CanonicalSendUserMessageV2) {
  validate(v);
  const w = new Writer();
  w.raw(Uint8Array.of(70, 67, 77, 50));
  w.u8(2);
  w.raw(uuid(v.request.client_submission_id));
  w.raw(uuid(v.session_id));
  w.raw(v.canonical_project_digest);
  w.u64(v.model_config_generation);
  w.raw(v.canonical_model_digest);
  w.text32(v.request.text);
  if (v.request.display_text === null) w.u8(0);
  else {
    w.u8(1);
    w.text32(v.request.display_text);
  }
  w.u16(v.request.tag_expansions.length);
  for (const t of v.request.tag_expansions) {
    w.text16(t.tool);
    w.text32(t.path);
    w.text32(t.detail);
    w.u8(t.ok ? 1 : 0);
  }
  if (v.request.forced_skill === null) w.u8(0);
  else {
    w.u8(1);
    w.text16(v.request.forced_skill);
  }
  w.u8(v.request.attachments.length);
  for (const a of v.request.attachments) {
    w.raw(uuid(a.attachment_id));
    w.u64(a.attachment_version);
    w.raw(a.checksum);
    w.u8(kindCode(a.kind));
  }
  return w.done();
}
class Reader {
  at = 0;
  constructor(readonly b: Uint8Array) {}
  raw(n: number) {
    const end = this.at + n;
    if (!Number.isSafeInteger(end) || end > this.b.length) throw new Error("truncated FCM2");
    const v = this.b.slice(this.at, end);
    this.at = end;
    return v;
  }
  u8() {
    return this.raw(1)[0]!;
  }
  u16() {
    const v = this.raw(2);
    return v[0]! * 256 + v[1]!;
  }
  u32() {
    const v = this.raw(4);
    return v[0]! * 0x1000000 + v[1]! * 0x10000 + v[2]! * 256 + v[3]!;
  }
  u64() {
    let v = 0n;
    for (const b of this.raw(8)) v = (v << 8n) | BigInt(b);
    return v;
  }
  text(n: number) {
    try {
      return decoder.decode(this.raw(n));
    } catch {
      throw new Error("invalid UTF-8");
    }
  }
  text16() {
    return this.text(this.u16());
  }
  text32() {
    return this.text(this.u32());
  }
}
export function decodeCanonicalSendUserMessageV2(b: Uint8Array): CanonicalSendUserMessageV2 {
  validateFcm2Length(b.length);
  const r = new Reader(b);
  if (r.text(4) !== "FCM2" || r.u8() !== 2) throw new Error("invalid FCM2 header");
  const client_submission_id = uuidString(r.raw(16)),
    session_id = uuidString(r.raw(16)),
    canonical_project_digest = r.raw(32),
    model_config_generation = r.u64(),
    canonical_model_digest = r.raw(32),
    text = r.text32();
  const dp = r.u8();
  if (dp > 1) throw new Error("invalid display presence");
  const display_text = dp ? r.text32() : null;
  const tc = r.u16();
  if (tc > 64) throw new Error("too many tags");
  const tag_expansions = [] as MessageTagExpansion[];
  for (let i = 0; i < tc; i++) {
    const tool = r.text16(),
      path = r.text32(),
      detail = r.text32(),
      ok = r.u8();
    if (ok > 1) throw new Error("invalid boolean");
    tag_expansions.push({ tool, path, detail, ok: ok === 1 });
  }
  const fp = r.u8();
  if (fp > 1) throw new Error("invalid forced skill presence");
  const forced_skill = fp ? r.text16() : null;
  const ac = r.u8();
  if (ac > 16) throw new Error("too many attachments");
  const attachments = [] as MessageAttachmentIdentity[];
  for (let i = 0; i < ac; i++) {
    const attachment_id = uuidString(r.raw(16)),
      attachment_version = r.u64(),
      checksum = r.raw(32),
      code = r.u8(),
      kind = ({ 1: "image", 2: "audio", 3: "video" } as const)[code as 1 | 2 | 3];
    if (!kind) throw new Error("unknown attachment kind");
    attachments.push({ attachment_id, attachment_version, checksum, kind });
  }
  if (r.at !== b.length) throw new Error("trailing FCM2 bytes");
  const v = {
    session_id,
    canonical_project_digest,
    model_config_generation,
    canonical_model_digest,
    request: {
      client_submission_id,
      text,
      display_text,
      tag_expansions,
      forced_skill,
      attachments,
    },
  };
  validate(v);
  return v;
}
async function sha256(b: Uint8Array) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(b).buffer));
}
export async function messageRequestDigest(v: CanonicalSendUserMessageV2) {
  const domain = encoder.encode("flycockpit-send-user-message-v2\0"),
    body = encodeCanonicalSendUserMessageV2(v),
    all = new Uint8Array(domain.length + body.length);
  all.set(domain);
  all.set(body, domain.length);
  return sha256(all);
}
export async function attachmentSetDigest(v: CanonicalSendUserMessageV2) {
  validate(v);
  const w = new Writer();
  w.u8(v.request.attachments.length);
  for (const a of v.request.attachments) {
    w.raw(uuid(a.attachment_id));
    w.u64(a.attachment_version);
    w.raw(a.checksum);
    w.u8(kindCode(a.kind));
  }
  const domain = encoder.encode("flycockpit-message-attachment-set-v1\0"),
    body = w.done(),
    all = new Uint8Array(domain.length + body.length);
  all.set(domain);
  all.set(body, domain.length);
  return sha256(all);
}
