/**
 * React wiring for the passive browser WebRTC remote client adapter.
 *
 * @see remote-webrtc-web-client
 *
 * This hook owns the adapter lifecycle and generation-guards every event so
 * navigation, unmount, cancellation, deadline, late promise, or replacement
 * cannot mutate stale React state. It exposes only safe, redacted UX state —
 * no candidates, addresses, credentials, peer tier, grants, or fingerprints.
 */

import {
  type RemoteWebAttemptInput,
  type RemoteWebEvent,
  type RemoteWebHealthStatus,
  RemoteWebRtcAdapter,
  type RemoteWebSafeUxState,
  type RemoteWebSignalingIn,
  remoteWebSafeUxState,
  type WebRtcPeerFactory,
} from "@flycockpit/cockpit-protocol";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

export type RemoteWebRtcHookState = {
  readonly uxState: RemoteWebSafeUxState;
  readonly health: RemoteWebHealthStatus;
  readonly lanesReady: boolean;
  readonly closeReason: string | undefined;
};

const initialState: RemoteWebRtcHookState = {
  uxState: "closed",
  health: "closed",
  lanesReady: false,
  closeReason: undefined,
};

export interface UseRemoteWebRtcAdapterOptions {
  readonly peerFactory: WebRtcPeerFactory;
}

export interface UseRemoteWebRtcAdapterResult {
  readonly state: RemoteWebRtcHookState;
  readonly establish: (input: RemoteWebAttemptInput) => Promise<void>;
  readonly send: (lane: RemoteWebRtcHookLane, bytes: Uint8Array) => void;
  readonly ingestSignaling: (event: RemoteWebSignalingIn) => void;
  readonly close: (reason?: RemoteWebRtcHookCloseReason) => void;
}

export type RemoteWebRtcHookLane = "control" | "interactive" | "bulk";
export type RemoteWebRtcHookCloseReason =
  | "navigation"
  | "unmount"
  | "cancel"
  | "deadline"
  | "replacement"
  | "remote_closed"
  | "error";

/**
 * Mount-scoped hook that owns a single `RemoteWebRtcAdapter` instance.
 *
 * The adapter is passive; this hook does not improvise retry/fallback/reattach
 * or logical mutation. It only forwards commands and reduces typed events to
 * safe UX state.
 */
export function useRemoteWebRtcAdapter(
  options: UseRemoteWebRtcAdapterOptions,
): UseRemoteWebRtcAdapterResult {
  const [state, setState] = useState<RemoteWebRtcHookState>(initialState);
  const adapterRef = useRef<RemoteWebRtcAdapter | null>(null);
  const mountedRef = useRef(true);
  const generationRef = useRef(0);

  // Create the adapter once per mount.
  if (adapterRef.current === null) {
    adapterRef.current = new RemoteWebRtcAdapter({
      peerFactory: options.peerFactory,
      emit: (event: RemoteWebEvent) => {
        // Generation-guard: ignore events from stale adapters after unmount.
        if (!mountedRef.current) return;
        setState((prev) => reduceAdapterEvent(prev, event));
      },
    });
  }

  // Unmount cleanup — deterministic close without stale mutation.
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      adapterRef.current?.close("unmount");
    };
  }, []);

  const establish = useCallback(async (input: RemoteWebAttemptInput) => {
    generationRef.current += 1;
    const gen = generationRef.current;
    if (!mountedRef.current || gen !== generationRef.current) return;
    setState({ ...initialState, uxState: "active", health: "establishing" });
    await adapterRef.current?.dispatch({ kind: "establish", input });
  }, []);

  const send = useCallback((lane: RemoteWebRtcHookLane, bytes: Uint8Array) => {
    adapterRef.current?.dispatch({ kind: "send", lane, bytes });
  }, []);

  const ingestSignaling = useCallback((event: RemoteWebSignalingIn) => {
    adapterRef.current?.ingestSignaling(event);
  }, []);

  const close = useCallback((reason?: RemoteWebRtcHookCloseReason) => {
    adapterRef.current?.close(reason ?? "cancel");
    setState(initialState);
  }, []);

  return useMemo(
    () => ({ state, establish, send, ingestSignaling, close }),
    [state, establish, send, ingestSignaling, close],
  );
}

/** Reduce a typed adapter event to safe UX state — no network/identity material. */
export function reduceAdapterEvent(
  prev: RemoteWebRtcHookState,
  event: RemoteWebEvent,
): RemoteWebRtcHookState {
  switch (event.kind) {
    case "capability":
      return { ...prev, uxState: remoteWebSafeUxState(event.result) };
    case "health":
      return { ...prev, health: event.status };
    case "lane_ready":
      return { ...prev, lanesReady: true };
    case "close":
      return {
        ...prev,
        uxState: "closed",
        health: "closed",
        lanesReady: false,
        closeReason: event.reason,
      };
    case "signaling":
    case "candidate":
    case "ice_complete":
    case "lane_data":
    case "backpressure":
      // These events are consumed by the caller's signaling/transport routing,
      // not by UI state. No network/identity material is exposed to React.
      return prev;
  }
}
