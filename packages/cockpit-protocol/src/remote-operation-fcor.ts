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
  if (resources.length > 0xffff || canonicalParams.length > U32_MAX) {
    throw new Error("FCOR field exceeds v1 length bound");
  }
  let size = 4 + 1 + 1 + kind.length + 2 + 4 + canonicalParams.length;
  for (const resource of resources) {
    const code = resourceKindCode(resource.kind);
    if (resource.value.length > U32_MAX) throw new Error("FCOR resource exceeds u32 length");
    validateStableResourceShape(code, resource.value);
    size += 1 + 4 + resource.value.length;
    if (!Number.isSafeInteger(size) || size > U32_MAX) {
      throw new Error("FCOR total length exceeds safe allocation bound");
    }
  }
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
