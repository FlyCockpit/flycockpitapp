export const FCOR_MAGIC = new Uint8Array([0x46, 0x43, 0x4f, 0x52]);
export const FCOR_SCHEMA_VERSION = 1;

export const remoteOperationResourceKinds = {
  session_uuid: 1,
  project_id: 2,
  project_root: 3,
  file_path: 4,
  terminal_uuid: 5,
  upload_uuid: 6,
  interrupt_uuid: 7,
  scheduler_id: 8,
  queue_uuid: 9,
  provider_model: 10,
  daemon_global: 11,
} as const;

export type RemoteOperationResource = {
  kind: string;
  value: Uint8Array;
};

declare const validatedFcorV1: unique symbol;
export type ValidatedFcorV1 = Uint8Array & { readonly [validatedFcorV1]: true };

const U32_MAX = 0xffffffff;
export const MAX_FCOR_V1_BYTES = U32_MAX;
export const MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES = 2_631_500;
export type CanonicalParamErrorCode =
  | "non_nfc"
  | "nul"
  | "invalid_unicode_scalar"
  | "duplicate_nfc_key";
export class CanonicalParamError extends Error {
  constructor(
    readonly code: CanonicalParamErrorCode,
    message: string,
  ) {
    super(message);
  }
}
export const sendUserMessageV2OpaqueRegistration = {
  requestKind: "send_user_message",
  magic: new Uint8Array([0x46, 0x43, 0x4d, 0x32]),
  maximumBytes: MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES,
  owner: "message-attachment-protocol-foundation",
} as const;

export type SendUserMessageV2FoundationDecoder = {
  readonly owner: "message-attachment-protocol-foundation";
  validate(bytes: Uint8Array): void;
};

export function validateRegisteredSendUserMessageV2(
  bytes: Uint8Array,
  foundationDecoder: SendUserMessageV2FoundationDecoder,
): void {
  const registration = sendUserMessageV2OpaqueRegistration;
  if (bytes.length > registration.maximumBytes) throw new Error("FCM2 exceeds registered maximum");
  if (!registration.magic.every((byte, index) => bytes[index] === byte)) {
    throw new Error("FCM2 has wrong magic");
  }
  if (foundationDecoder.owner !== registration.owner)
    throw new Error("FCM2 decoder owner mismatch");
  foundationDecoder.validate(bytes);
}

export class CanonicalParamsV1 {
  readonly #bytes: number[] = [];
  pushU8(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) throw new Error("u8 out of range");
    this.#bytes.push(value);
  }
  pushBool(value: boolean): void {
    this.pushU8(value ? 1 : 0);
  }
  pushU16(value: number): void {
    this.pushFixed(value, 2);
  }
  pushU32(value: number): void {
    this.pushFixed(value, 4);
  }
  pushU64(value: bigint): void {
    this.pushBigFixed(value, 8);
  }
  pushI64(value: bigint): void {
    if (value < -(1n << 63n) || value > (1n << 63n) - 1n) throw new Error("i64 out of range");
    this.pushBigFixed(BigInt.asUintN(64, value), 8);
  }
  pushUuid(value: Uint8Array): void {
    if (value.length !== 16) throw new Error("UUID must be 16 raw bytes");
    this.#bytes.push(...value);
  }
  pushBytes(value: Uint8Array): void {
    if (value.length > U32_MAX) throw new Error("canonical bytes exceed u32 length");
    this.pushU32(value.length);
    this.#bytes.push(...value);
  }
  pushString(value: string): void {
    if (hasUnpairedSurrogate(value))
      throw new CanonicalParamError("invalid_unicode_scalar", "invalid Unicode scalar input");
    if (value.includes("\0")) throw new CanonicalParamError("nul", "canonical string contains NUL");
    if (value.normalize("NFC") !== value)
      throw new CanonicalParamError("non_nfc", "canonical string is not NFC");
    this.pushBytes(new TextEncoder().encode(value));
  }
  pushOptional<T>(
    value: T | undefined,
    encode: (params: CanonicalParamsV1, value: T) => void,
  ): void {
    if (value === undefined) {
      this.pushU8(0);
      return;
    }
    const nested = new CanonicalParamsV1();
    encode(nested, value);
    this.pushU8(1);
    this.#bytes.push(...nested.finish());
  }
  pushList<T>(values: readonly T[], encode: (params: CanonicalParamsV1, value: T) => void): void {
    if (values.length > U32_MAX) throw new Error("list exceeds u32 count");
    const encoded = values.map((value) => {
      const item = new CanonicalParamsV1();
      encode(item, value);
      return item.finish();
    });
    this.pushU32(encoded.length);
    for (const item of encoded) this.#bytes.push(...item);
  }
  pushStringMap(entries: Iterable<readonly [string, string]>): void {
    const encoded = [...entries].map(([key, value]) => {
      if (hasUnpairedSurrogate(key))
        throw new CanonicalParamError("invalid_unicode_scalar", "invalid Unicode scalar input");
      if (key.includes("\0"))
        throw new CanonicalParamError("nul", "canonical map key contains NUL");
      const normalizedKey = key.normalize("NFC");
      const encodedKey = new CanonicalParamsV1();
      encodedKey.pushString(normalizedKey);
      const encodedValue = new CanonicalParamsV1();
      encodedValue.pushString(value);
      return {
        normalizedKey,
        key: encodedKey.finish(),
        value: encodedValue.finish(),
      };
    });
    encoded.sort((left, right) => compareBytes(left.key, right.key));
    for (let index = 1; index < encoded.length; index += 1) {
      if (encoded[index - 1].normalizedKey === encoded[index].normalizedKey)
        throw new CanonicalParamError("duplicate_nfc_key", "duplicate NFC map key");
    }
    this.pushU32(encoded.length);
    for (const entry of encoded) this.#bytes.push(...entry.key, ...entry.value);
  }
  finish(): Uint8Array {
    return Uint8Array.from(this.#bytes);
  }
  private pushFixed(value: number, width: number): void {
    if (!Number.isSafeInteger(value) || value < 0 || value > 2 ** (width * 8) - 1)
      throw new Error("integer out of range");
    this.pushBigFixed(BigInt(value), width);
  }
  private pushBigFixed(value: bigint, width: number): void {
    if (value < 0n || value >= 1n << BigInt(width * 8)) throw new Error("integer out of range");
    for (let shift = width - 1; shift >= 0; shift -= 1)
      this.#bytes.push(Number((value >> BigInt(shift * 8)) & 0xffn));
  }
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}

export function checkedFcorV1Size(
  requestKindLength: number,
  resourceValueLengths: readonly number[],
  paramsLength: number,
): number {
  if (
    !Number.isSafeInteger(requestKindLength) ||
    requestKindLength < 1 ||
    requestKindLength > 255
  ) {
    throw new Error("invalid FCOR request kind length");
  }
  if (!Number.isSafeInteger(paramsLength) || paramsLength < 0 || paramsLength > U32_MAX) {
    throw new Error("FCOR params exceed u32 length");
  }
  if (resourceValueLengths.length > 0xffff) throw new Error("too many FCOR resources");
  let total = 4 + 1 + 1 + requestKindLength + 2 + 4 + paramsLength;
  for (const length of resourceValueLengths) {
    if (!Number.isSafeInteger(length) || length < 0 || length > U32_MAX) {
      throw new Error("FCOR resource exceeds u32 length");
    }
    total += 5 + length;
    if (!Number.isSafeInteger(total) || total > MAX_FCOR_V1_BYTES) {
      throw new Error("FCOR total length exceeds maximum");
    }
  }
  if (total > MAX_FCOR_V1_BYTES) throw new Error("FCOR total length exceeds maximum");
  return total;
}

function resourceKindCode(kind: string): number {
  const code = remoteOperationResourceKinds[kind as keyof typeof remoteOperationResourceKinds];
  if (code === undefined) throw new Error(`unknown FCOR resource kind: ${kind}`);
  return code;
}

function validateStableResourceShape(kind: number, value: Uint8Array): void {
  if ([1, 5, 6, 7, 9].includes(kind) && value.length !== 16) {
    throw new Error("UUID resource must be exactly 16 bytes");
  }
  if (kind === 11 && value.length !== 0) {
    throw new Error("daemon_global resource must be empty");
  }
  // Text and path value semantics belong to the generated request descriptor;
  // paths in particular must be resolved by daemon authorization first. This
  // function brands only the closed outer FCOR structure.
}

export function encodeFcorV1(
  requestKind: string,
  resources: readonly RemoteOperationResource[],
  canonicalParams: Uint8Array,
): Uint8Array {
  const kind = new TextEncoder().encode(requestKind);
  if (kind.length < 1 || kind.length > 255 || !/^[a-z0-9_]+$/.test(requestKind)) {
    throw new Error("request kind must be 1..255 lowercase ASCII bytes");
  }
  const resourceLengths: number[] = [];
  for (const resource of resources) {
    const code = resourceKindCode(resource.kind);
    validateStableResourceShape(code, resource.value);
    resourceLengths.push(resource.value.length);
  }
  const size = checkedFcorV1Size(kind.length, resourceLengths, canonicalParams.length);
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  let offset = 0;
  out.set(FCOR_MAGIC, offset);
  offset += 4;
  out[offset++] = FCOR_SCHEMA_VERSION;
  out[offset++] = kind.length;
  out.set(kind, offset);
  offset += kind.length;
  view.setUint16(offset, resources.length, false);
  offset += 2;
  for (const resource of resources) {
    out[offset++] = resourceKindCode(resource.kind);
    view.setUint32(offset, resource.value.length, false);
    offset += 4;
    out.set(resource.value, offset);
    offset += resource.value.length;
  }
  view.setUint32(offset, canonicalParams.length, false);
  offset += 4;
  out.set(canonicalParams, offset);
  return out;
}

export function validateFcorV1(bytes: Uint8Array): ValidatedFcorV1 {
  if (bytes.length < 12 || !FCOR_MAGIC.every((byte, index) => bytes[index] === byte)) {
    throw new Error("invalid FCOR magic or length");
  }
  if (bytes[4] !== FCOR_SCHEMA_VERSION) throw new Error("unsupported FCOR schema");
  let offset = 5;
  const kindLength = bytes[offset++];
  if (kindLength === 0 || offset + kindLength + 2 > bytes.length) {
    throw new Error("invalid FCOR request kind length");
  }
  const kind = new TextDecoder("utf-8", { fatal: true }).decode(
    bytes.subarray(offset, offset + kindLength),
  );
  if (!/^[a-z0-9_]+$/.test(kind)) throw new Error("invalid FCOR request kind");
  offset += kindLength;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = view.getUint16(offset, false);
  offset += 2;
  for (let index = 0; index < count; index += 1) {
    if (offset + 5 > bytes.length) throw new Error("truncated FCOR resource");
    const resourceKind = bytes[offset++];
    if (resourceKind < 1 || resourceKind > 11) throw new Error("unknown FCOR resource kind");
    const length = view.getUint32(offset, false);
    offset += 4;
    if (offset + length > bytes.length) throw new Error("truncated FCOR resource value");
    validateStableResourceShape(resourceKind, bytes.subarray(offset, offset + length));
    offset += length;
  }
  if (offset + 4 > bytes.length) throw new Error("missing FCOR params length");
  const paramsLength = view.getUint32(offset, false);
  offset += 4;
  if (offset + paramsLength !== bytes.length) throw new Error("truncated or trailing FCOR bytes");
  return bytes as ValidatedFcorV1;
}

export async function hashFcorV1(bytes: Uint8Array): Promise<Uint8Array> {
  const validated = validateFcorV1(bytes);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", validated));
}
