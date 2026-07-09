import {
  RemoteSessionClient,
  type RemoteSessionClientOptions,
} from "@flycockpit/cockpit-protocol/client";

type NativeRemoteSessionClientOptions = Omit<RemoteSessionClientOptions, "idPrefix"> & {
  idPrefix?: string;
};

export function createNativeRemoteSessionClient(options: NativeRemoteSessionClientOptions) {
  return new RemoteSessionClient({ ...options, idPrefix: options.idPrefix ?? "native" });
}
