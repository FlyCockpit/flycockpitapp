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
  kind: keyof typeof remoteOperationResourceKinds;
  value: Uint8Array;
};

export function encodeFcorV1(
  requestKind: string,
  resources: readonly RemoteOperationResource[],
  canonicalParams: Uint8Array,
): Uint8Array {
  const kind = new TextEncoder().encode(requestKind);
  if (kind.length < 1 || kind.length > 255 || !/^[a-z0-9_]+$/.test(requestKind)) {
    throw new Error("request kind must be 1..255 lowercase ASCII bytes");
  }
  if (resources.length > 0xffff || canonicalParams.length > 0xffffffff) {
    throw new Error("FCOR field exceeds v1 length bound");
  }
  const size =
    4 + 1 + 1 + kind.length + 2 +
    resources.reduce((sum, resource) => sum + 1 + 4 + resource.value.length, 0) +
    4 + canonicalParams.length;
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
    out[offset++] = remoteOperationResourceKinds[resource.kind];
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
