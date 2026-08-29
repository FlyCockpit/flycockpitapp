import {
  type HistoryEntry,
  type InterruptOption,
  type SessionSummary,
} from "@flycockpit/cockpit-protocol";
import { shouldRetainUserMessageSubmission } from "@flycockpit/cockpit-protocol/client";
import * as Clipboard from "expo-clipboard";
import * as ImagePicker from "expo-image-picker";
import { useLocalSearchParams } from "expo-router";
import { Button, Card, Chip, Input, Spinner, Surface, TextField } from "heroui-native";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  FlatList,
  type NativeScrollEvent,
  type NativeSyntheticEvent,
  Text,
  View,
} from "react-native";
import { Container } from "@/components/container";
import { useNativeRemoteClient } from "@/hooks/use-native-remote-client";
import {
  cancelPausedWorkAction,
  composerSendDisabled,
  emptyNativeDaemonState,
  resumePausedWorkAction,
} from "@/utils/daemon-state";
import {
  emptyNativeHistoryPagingState,
  loadNativeHistoryPage,
  markNativeHistoryPageLoading,
  NativeHistoryPagingCoordinator,
  type NativeHistoryPagingState,
  nativeTranscriptScreenScrollOwners,
  pagingFromNativeHistory,
} from "@/utils/history-paging";
import { activeModelView } from "@/utils/inference-failure-view";
import {
  type InterruptSelection,
  type InterruptView,
  interruptView,
  type RiskTone,
  resolveFromSelection,
} from "@/utils/interrupt-view";
import {
  contentOffsetAfterLayoutChange,
  shouldApplyPrependAnchor,
  shouldLoadOlderHistory,
} from "@/utils/scroll-anchor";
import { NativeAttachCoordinator } from "@/utils/session-attach";
import {
  acceptedClientSubmissionIdsFromEvent,
  appendOptimisticUserMessage,
  clearAcceptedRetryDrafts,
  clientSubmissionIdsFromHistory,
  forgetUserMessageSubmission,
  interruptDecisionView,
  isCurrentUserMessageSubmission,
  type NativeHistoryEntry,
  nativeAttachRuntimeState,
  prepareUserMessageSubmission,
  type RetainedUserMessageSubmission,
  type RetainedUserMessageSubmissions,
  reconcileAcceptedRetrySubmissions,
  reduceNativeSessionEvent,
  removeOptimisticUserMessage,
  restoreRetainedUserMessagesAfterAttach,
  retainUserMessageSubmission,
  toNativeHistoryEntry,
  warnNativeSessionEvent,
} from "@/utils/session-events";

/** Satisfies native_history_virtualized_list: one FlatList owns transcript scrolling. */
const transcriptScrollOwners = nativeTranscriptScreenScrollOwners();
const TranscriptList = FlatList;

type InterruptDraft = {
  text: string;
  selectedIds: string[];
};

function formatSessionTitle(session: SessionSummary) {
  return session.title || session.short_id || session.session_id;
}

function sessionActivityLabel(session: SessionSummary) {
  const activityState = (session as { activity_state?: unknown }).activity_state;
  return typeof activityState === "string" ? activityState.replaceAll("_", " ") : "idle";
}

function historyText(entry: NativeHistoryEntry) {
  if (entry.kind === "user_message") return entry.text;
  if (entry.kind === "user_note") return entry.text;
  if (entry.kind === "assistant_text") return entry.text;
  if (entry.kind === "assistant_reasoning") return entry.text;
  if (entry.kind === "tool_call") return entry.name + " " + entry.status;
  if (entry.kind === "boundary") return entry.label;
  if (entry.kind === "subagent_report") return entry.title + "\n" + entry.body;
  if (entry.kind === "interrupt") return entry.interrupt.title;
  if (entry.kind === "interrupt_decision") {
    const view = interruptDecisionView(entry);
    if (!view) return "";
    const status = view.cancelled ? "Interrupt cancelled" : "Interrupt resolved";
    const lines = view.lines.map((line) => `${line.prompt}: ${line.answer}`).join("\n");
    return lines ? `${status}\n${lines}` : status;
  }
  return "";
}

export default function ProjectSessions() {
  const params = useLocalSearchParams<{
    instanceId?: string;
    projectId?: string;
    projectRoot?: string;
    name?: string;
    session?: string;
    interrupt?: string;
  }>();
  const instanceId = Array.isArray(params.instanceId) ? params.instanceId[0] : params.instanceId;
  const projectRootParam = Array.isArray(params.projectRoot)
    ? params.projectRoot[0]
    : params.projectRoot;
  const projectRoot = projectRootParam
    ? String(projectRootParam)
    : decodeURIComponent(String(params.projectId ?? ""));
  const projectId = decodeURIComponent(String(params.projectId ?? projectRoot));
  const initialSession = Array.isArray(params.session) ? params.session[0] : params.session;
  const projectName = Array.isArray(params.name) ? params.name[0] : params.name;
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(initialSession ?? null);
  const [history, setHistory] = useState<NativeHistoryEntry[]>([]);
  const [historyPaging, setHistoryPaging] = useState<NativeHistoryPagingState>(() =>
    emptyNativeHistoryPagingState(),
  );
  const [messagesBySession, setMessagesBySession] = useState<Record<string, string>>({});
  const [sendingMessage, setSendingMessage] = useState(false);
  const [retrySubmissionsBySession, setRetrySubmissionsBySession] = useState<
    Record<string, RetainedUserMessageSubmission | undefined>
  >({});
  const retrySubmissionsRef = useRef<Record<string, RetainedUserMessageSubmission | undefined>>({});
  const [interruptDrafts, setInterruptDrafts] = useState<Record<string, InterruptDraft>>({});
  const [busy, setBusy] = useState(false);
  const [loadingSessions, setLoadingSessions] = useState(false);
  const [attachingSessionId, setAttachingSessionId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [daemonState, setDaemonState] = useState(emptyNativeDaemonState);
  const [activeModel, setActiveModel] = useState<ReturnType<typeof activeModelView> | null>(null);
  const selectedSessionRef = useRef<string | null>(initialSession ?? null);
  const historyRef = useRef<NativeHistoryEntry[]>([]);
  const historyPagingRef = useRef<NativeHistoryPagingState>(emptyNativeHistoryPagingState());
  const daemonStateRef = useRef(emptyNativeDaemonState);
  const activeModelStateRef = useRef<Parameters<typeof activeModelView>[0]>(null);
  const pendingUserSubmissionsRef = useRef<RetainedUserMessageSubmissions>(new Map());
  const latestSubmitIdRef = useRef<string | null>(null);
  const sessionListRequestRef = useRef(0);
  const attachCoordinatorRef = useRef(new NativeAttachCoordinator());
  const historyPagingCoordinatorRef = useRef(new NativeHistoryPagingCoordinator());
  const attachLifecycleRef = useRef<{
    client: object | null;
    connectionEpoch: number;
  }>({ client: null, connectionEpoch: 0 });
  const lastAutoAttachRef = useRef<{ client: object; connectionEpoch: number } | null>(null);
  const transcriptListRef = useRef<FlatList<NativeHistoryEntry>>(null);
  const scrollOffsetYRef = useRef(0);
  const contentHeightRef = useRef(0);
  const prependPendingRef = useRef(false);

  const message = selectedSessionId ? (messagesBySession[selectedSessionId] ?? "") : "";
  const retrySubmission = selectedSessionId
    ? retrySubmissionsBySession[selectedSessionId]
    : undefined;
  const setSessionMessage = (sessionId: string, value: string | ((current: string) => string)) => {
    setMessagesBySession((current) => {
      const previous = current[sessionId] ?? "";
      const next = typeof value === "function" ? value(previous) : value;
      return { ...current, [sessionId]: next };
    });
  };
  const setSessionRetry = (sessionId: string, submission: RetainedUserMessageSubmission | null) => {
    const next = {
      ...retrySubmissionsRef.current,
      [sessionId]: submission ?? undefined,
    };
    retrySubmissionsRef.current = next;
    setRetrySubmissionsBySession(next);
  };

  const reconcileAcceptedRetryDrafts = useCallback((acceptedIds: string[]) => {
    const reconciled = reconcileAcceptedRetrySubmissions(retrySubmissionsRef.current, acceptedIds);
    if (reconciled.retries !== retrySubmissionsRef.current) {
      retrySubmissionsRef.current = reconciled.retries;
      setRetrySubmissionsBySession(reconciled.retries);
    }
    if (reconciled.accepted.length > 0) {
      setMessagesBySession((current) => clearAcceptedRetryDrafts(current, reconciled.accepted));
    }
  }, []);

  const handleSessionEvent = useCallback(
    (raw: unknown) => {
      const acceptedIds = acceptedClientSubmissionIdsFromEvent(raw, selectedSessionRef.current);
      for (const id of acceptedIds) {
        forgetUserMessageSubmission(pendingUserSubmissionsRef.current, id);
      }
      reconcileAcceptedRetryDrafts(acceptedIds);
      const result = reduceNativeSessionEvent(
        {
          history: historyRef.current,
          selectedSessionId: selectedSessionRef.current,
          daemonState: daemonStateRef.current,
          activeModel: activeModelStateRef.current,
        },
        raw,
      );
      warnNativeSessionEvent(result);
      historyRef.current = result.state.history;
      daemonStateRef.current = result.state.daemonState ?? emptyNativeDaemonState;
      activeModelStateRef.current = result.state.activeModel ?? null;
      setHistory(result.state.history);
      setDaemonState(daemonStateRef.current);
      setActiveModel(activeModelView(activeModelStateRef.current));
    },
    [reconcileAcceptedRetryDrafts],
  );

  const { client, status, connectionEpoch, tokenQuery } = useNativeRemoteClient(
    instanceId,
    handleSessionEvent,
  );
  const clientRef = useRef(client);
  const statusRef = useRef(status);
  const connectionEpochRef = useRef(connectionEpoch);
  clientRef.current = client;
  statusRef.current = status;
  connectionEpochRef.current = connectionEpoch;

  useEffect(() => {
    selectedSessionRef.current = selectedSessionId;
  }, [selectedSessionId]);

  const unresolvedInterrupts = useMemo(
    () => history.filter((entry) => entry.kind === "interrupt" && !entry.interrupt.resolved),
    [history],
  );
  const attachmentReadyFor = (sessionId: string) => {
    const currentClient = clientRef.current;
    return Boolean(
      currentClient &&
        statusRef.current === "connected" &&
        attachCoordinatorRef.current.isReady(currentClient, connectionEpochRef.current, sessionId),
    );
  };
  const selectedAttachmentReady = selectedSessionId ? attachmentReadyFor(selectedSessionId) : false;
  const modelView = activeModel ?? activeModelView(activeModelStateRef.current);
  const uiBusy = busy || loadingSessions || attachingSessionId !== null;
  const sendDisabled = composerSendDisabled({
    message,
    busy: uiBusy || sendingMessage || !selectedAttachmentReady,
    draining: daemonState.draining,
    repairRequired: daemonState.repairRequired,
  });

  const applyHistoryPaging = (next: NativeHistoryPagingState) => {
    historyPagingRef.current = next;
    setHistoryPaging(next);
  };

  const loadOlderHistory = useCallback(async () => {
    const pageClient = clientRef.current;
    const sessionId = selectedSessionRef.current;
    const epoch = connectionEpochRef.current;
    if (!pageClient || !sessionId || statusRef.current !== "connected") return;
    if (!attachmentReadyFor(sessionId)) return;
    const paging = historyPagingRef.current;
    if (!paging.hasMore || paging.isLoading || historyPagingCoordinatorRef.current.hasInFlight()) {
      return;
    }

    const requestGeneration = historyPagingCoordinatorRef.current.currentRequestGeneration();
    applyHistoryPaging(markNativeHistoryPageLoading(paging));

    const result = await loadNativeHistoryPage({
      coordinator: historyPagingCoordinatorRef.current,
      client: pageClient,
      connectionEpoch: epoch,
      sessionId,
      requestGeneration,
      paging: { ...paging, isLoading: true, error: null },
      history: historyRef.current,
      // Capture history only after the attempt is confirmed current so live
      // appends during the request are retained.
      resolveHistory: () => historyRef.current,
    });

    if (result.kind === "success") {
      // Arm prepend anchor only when the successful merge actually grew the
      // list from older rows (not for live/resize layout changes mid-flight).
      if (result.prepended) {
        prependPendingRef.current = true;
      }
      historyRef.current = result.history;
      setHistory(result.history);
      applyHistoryPaging(result.paging);
      return;
    }

    if (result.kind === "error") {
      prependPendingRef.current = false;
      applyHistoryPaging(result.paging);
      return;
    }
    // skipped or stale: do not mutate history, cursor, error, or loading.
    // A stale result must not clear a newer request's isLoading flag.
  }, []);

  const loadOlderHistoryRef = useRef(loadOlderHistory);
  loadOlderHistoryRef.current = loadOlderHistory;

  const onTranscriptScroll = useCallback((event: NativeSyntheticEvent<NativeScrollEvent>) => {
    const offsetY = event.nativeEvent.contentOffset.y;
    scrollOffsetYRef.current = offsetY;
    if (shouldLoadOlderHistory({ offsetY })) {
      void loadOlderHistoryRef.current();
    }
  }, []);

  const onTranscriptContentSizeChange = useCallback((_width: number, height: number) => {
    const previousHeight = contentHeightRef.current;
    const grew = height > previousHeight;
    if (
      shouldApplyPrependAnchor({
        prependPending: prependPendingRef.current,
        contentGrewFromPrepend: grew,
      })
    ) {
      const nextOffset = contentOffsetAfterLayoutChange({
        previousOffsetY: scrollOffsetYRef.current,
        prependPending: true,
        previousContentHeight: previousHeight,
        nextContentHeight: height,
      });
      transcriptListRef.current?.scrollToOffset({ offset: nextOffset, animated: false });
      scrollOffsetYRef.current = nextOffset;
      prependPendingRef.current = false;
    } else if (prependPendingRef.current && !grew) {
      // Prepend completed with no measurable growth (empty/overlap-only page).
      prependPendingRef.current = false;
    }
    contentHeightRef.current = height;
  }, []);

  const attach = async (sessionId: string) => {
    const attachClient = clientRef.current;
    const attachEpoch = connectionEpochRef.current;
    if (!attachClient || statusRef.current !== "connected") return;
    const coordinator = attachCoordinatorRef.current;
    if (!coordinator.needsAttach(attachClient, attachEpoch, sessionId)) return;
    // Switching sessions invalidates any in-flight older-page request.
    historyPagingCoordinatorRef.current.bumpRequestGeneration();
    const attempt = coordinator.begin(attachClient, attachEpoch, sessionId);
    const attemptIsCurrent = () =>
      statusRef.current === "connected" &&
      coordinator.isCurrent(attempt, clientRef.current, connectionEpochRef.current);

    setAttachingSessionId(sessionId);
    setError(null);
    try {
      const result = await attachClient.attach({ session_id: sessionId, interactive: true });
      if (!attemptIsCurrent()) return;
      const acceptedIds = clientSubmissionIdsFromHistory(result.history);
      const nextHistory = restoreRetainedUserMessagesAfterAttach(
        result.history.map((entry: HistoryEntry, index: number) =>
          toNativeHistoryEntry(entry, index),
        ),
        sessionId,
        pendingUserSubmissionsRef.current,
      );
      const runtime = nativeAttachRuntimeState(result, daemonStateRef.current);
      if (!coordinator.markApplied(attempt, clientRef.current, connectionEpochRef.current)) return;

      for (const id of acceptedIds) {
        forgetUserMessageSubmission(pendingUserSubmissionsRef.current, id);
      }
      reconcileAcceptedRetryDrafts(acceptedIds);
      // Attach starts a fresh paging window for this session/generation.
      historyPagingCoordinatorRef.current.bumpRequestGeneration();
      const nextPaging = pagingFromNativeHistory(nextHistory);
      setSelectedSessionId(sessionId);
      selectedSessionRef.current = sessionId;
      historyRef.current = nextHistory;
      historyPagingRef.current = nextPaging;
      daemonStateRef.current = runtime.daemonState;
      activeModelStateRef.current = runtime.activeModel;
      setHistory(nextHistory);
      setHistoryPaging(nextPaging);
      setDaemonState(runtime.daemonState);
      setActiveModel(activeModelView(runtime.activeModel));
      prependPendingRef.current = false;
      const pending = [...pendingUserSubmissionsRef.current.values()].filter(
        (submission) => submission.sessionId === sessionId,
      );
      for (const submission of pending) {
        if (!attemptIsCurrent()) return;
        const id = submission.params.client_submission_id;
        if (!pendingUserSubmissionsRef.current.has(id)) continue;
        try {
          await attachClient.sendUserMessage(submission.params);
        } catch (replayError) {
          if (!attemptIsCurrent()) return;
          if (
            shouldRetainUserMessageSubmission(replayError) &&
            pendingUserSubmissionsRef.current.has(id)
          ) {
            setSessionMessage(sessionId, (current) => current || submission.params.text);
            setSessionRetry(sessionId, submission);
            break;
          }
          forgetUserMessageSubmission(pendingUserSubmissionsRef.current, id);
          if (retrySubmissionsRef.current[sessionId]?.params.client_submission_id === id) {
            setSessionRetry(sessionId, null);
          }
          const withoutRejected = removeOptimisticUserMessage(historyRef.current, id);
          historyRef.current = withoutRejected;
          setHistory(withoutRejected);
        }
      }
    } catch (attachError) {
      if (attemptIsCurrent()) {
        setError(attachError instanceof Error ? attachError.message : "Could not attach session.");
      }
    } finally {
      if (coordinator.finish(attempt, clientRef.current, connectionEpochRef.current)) {
        setAttachingSessionId(null);
      }
    }
  };

  const loadSessions = async () => {
    const loadClient = clientRef.current;
    const loadEpoch = connectionEpochRef.current;
    if (!loadClient || statusRef.current !== "connected") return;
    const requestId = ++sessionListRequestRef.current;
    setLoadingSessions(true);
    setError(null);
    try {
      const result = await loadClient.listSessions({ project_id: projectId });
      if (
        loadClient !== clientRef.current ||
        loadEpoch !== connectionEpochRef.current ||
        requestId !== sessionListRequestRef.current ||
        statusRef.current !== "connected"
      )
        return;
      setSessions(result.sessions);
      const nextSession = selectedSessionRef.current ?? result.sessions[0]?.session_id ?? null;
      setSelectedSessionId(nextSession);
      selectedSessionRef.current = nextSession;
      if (nextSession) void attach(nextSession);
    } catch (loadError) {
      if (
        loadClient === clientRef.current &&
        loadEpoch === connectionEpochRef.current &&
        requestId === sessionListRequestRef.current
      ) {
        setError(loadError instanceof Error ? loadError.message : "Could not load sessions.");
      }
    } finally {
      if (
        loadClient === clientRef.current &&
        loadEpoch === connectionEpochRef.current &&
        requestId === sessionListRequestRef.current
      ) {
        setLoadingSessions(false);
      }
    }
  };

  const sendMessage = async () => {
    if (
      !client ||
      !selectedSessionId ||
      !message.trim() ||
      sendingMessage ||
      !attachmentReadyFor(selectedSessionId) ||
      daemonState.repairRequired
    )
      return;
    const sessionId = selectedSessionId;
    const text = message.trim();
    setSessionMessage(sessionId, "");
    setSendingMessage(true);
    const prepared = prepareUserMessageSubmission(
      sessionId,
      text,
      retrySubmission?.sessionId === sessionId && retrySubmission.params.text === text
        ? retrySubmission
        : undefined,
    );
    const submission = retainUserMessageSubmission(
      pendingUserSubmissionsRef.current,
      prepared.submission,
    );
    const isRetry = prepared.isRetry || submission !== prepared.submission;
    latestSubmitIdRef.current = submission.params.client_submission_id;
    if (!isRetry) {
      const nextHistory = appendOptimisticUserMessage(
        historyRef.current,
        submission.params.display_text ?? submission.params.text,
        submission.params.client_submission_id,
      );
      historyRef.current = nextHistory;
      setHistory(nextHistory);
    }
    try {
      await client.sendUserMessage(submission.params);
      // Queue ACK is not durable. Keep the exact request until the daemon's
      // recorded/fold event or a later attach snapshot carries its receipt.
    } catch (sendError) {
      const isCurrentSubmission = isCurrentUserMessageSubmission(
        selectedSessionRef.current,
        latestSubmitIdRef.current,
        submission,
      );
      const retainable = shouldRetainUserMessageSubmission(sendError);
      if (
        retainable &&
        !pendingUserSubmissionsRef.current.has(submission.params.client_submission_id)
      ) {
        // A durable fold/record/attach receipt won the race with the
        // ambiguous transport result, so acceptance is authoritative.
        setSessionRetry(sessionId, null);
        return;
      }
      if (isCurrentSubmission) {
        setError(sendError instanceof Error ? sendError.message : "Could not send message.");
      }
      setSessionMessage(sessionId, (current) => current || text);
      if (retainable) {
        setSessionRetry(sessionId, submission);
      } else {
        forgetUserMessageSubmission(
          pendingUserSubmissionsRef.current,
          submission.params.client_submission_id,
        );
        setSessionRetry(sessionId, null);
        if (isCurrentSubmission) {
          const historyWithoutOptimistic = removeOptimisticUserMessage(
            historyRef.current,
            submission.params.client_submission_id,
          );
          historyRef.current = historyWithoutOptimistic;
          setHistory(historyWithoutOptimistic);
        }
      }
    } finally {
      setSendingMessage(false);
    }
  };

  const addImage = async () => {
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ["images"],
      quality: 0.85,
    });
    if (result.canceled || !result.assets[0]) return;
    setError(
      "Image upload is not available for remote sessions yet. The app will not send local file paths as message text.",
    );
  };

  const pasteClipboard = async () => {
    const text = await Clipboard.getStringAsync();
    if (text && selectedSessionId) {
      setSessionMessage(selectedSessionId, (current) => (current ? current + "\n" : "") + text);
    }
  };

  const copyFixCommand = async () => {
    const command = daemonState.sandboxNotice?.fixCommand;
    if (command) await Clipboard.setStringAsync(command);
  };

  const resumePausedWork = async () => {
    if (!client || !daemonState.pausedWork || !attachmentReadyFor(daemonState.pausedWork.sessionId))
      return;
    setBusy(true);
    setError(null);
    try {
      await resumePausedWorkAction(client, daemonState);
    } catch (resumeError) {
      setError(
        resumeError instanceof Error ? resumeError.message : "Could not resume paused work.",
      );
    } finally {
      setBusy(false);
    }
  };

  const cancelPausedWork = async () => {
    if (!client || !daemonState.pausedWork || !attachmentReadyFor(daemonState.pausedWork.sessionId))
      return;
    setBusy(true);
    setError(null);
    try {
      await cancelPausedWorkAction(client, daemonState);
    } catch (cancelError) {
      setError(
        cancelError instanceof Error ? cancelError.message : "Could not cancel paused work.",
      );
    } finally {
      setBusy(false);
    }
  };

  const setInterruptText = (interruptId: string, text: string) => {
    setInterruptDrafts((current) => ({
      ...current,
      [interruptId]: { text, selectedIds: current[interruptId]?.selectedIds ?? [] },
    }));
  };

  const toggleInterruptSelection = (interruptId: string, optionId: string) => {
    setInterruptDrafts((current) => {
      const draft = current[interruptId] ?? { text: "", selectedIds: [] };
      const selectedIds = draft.selectedIds.includes(optionId)
        ? draft.selectedIds.filter((id) => id !== optionId)
        : [...draft.selectedIds, optionId];
      return { ...current, [interruptId]: { ...draft, selectedIds } };
    });
  };

  const resolveInterrupt = async (interruptId: string, selection: InterruptSelection) => {
    if (!client || !selectedSessionId || !attachmentReadyFor(selectedSessionId)) return;
    const interrupt = unresolvedInterrupts.find(
      (entry) => entry.kind === "interrupt" && entry.interrupt.interruptId === interruptId,
    );
    if (interrupt?.kind !== "interrupt") return;
    setBusy(true);
    setError(null);
    try {
      await client.resolveInterrupt(
        interruptId,
        resolveFromSelection(interrupt.interrupt.question, selection),
      );
      setInterruptDrafts((current) => {
        const { [interruptId]: _resolved, ...remaining } = current;
        return remaining;
      });
    } catch (resolveError) {
      setError(
        resolveError instanceof Error ? resolveError.message : "Could not resolve interrupt.",
      );
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    const previous = attachLifecycleRef.current;
    const lifecycleChanged =
      previous.client !== client || previous.connectionEpoch !== connectionEpoch;
    if (lifecycleChanged || status !== "connected") {
      sessionListRequestRef.current += 1;
      setLoadingSessions(false);
      attachCoordinatorRef.current.invalidate();
      historyPagingCoordinatorRef.current.invalidate();
      historyPagingRef.current = emptyNativeHistoryPagingState();
      setHistoryPaging(emptyNativeHistoryPagingState());
      prependPendingRef.current = false;
      setAttachingSessionId(null);
    }
    attachLifecycleRef.current = { client, connectionEpoch };
  }, [client, connectionEpoch, status]);

  useEffect(() => {
    if (status === "connected" && sessions.length === 0) loadSessions();
  }, [status, sessions.length]);

  useEffect(() => {
    if (!client || status !== "connected" || connectionEpoch === 0) return;
    const previous = lastAutoAttachRef.current;
    if (previous?.client === client && previous.connectionEpoch === connectionEpoch) return;
    lastAutoAttachRef.current = { client, connectionEpoch };
    const sessionId = selectedSessionRef.current;
    if (sessionId) void attach(sessionId);
  }, [client, status, connectionEpoch]);

  const listHeader = (
    <View className="p-6 pb-0">
      <View className="py-4 mb-4">
        <Text className="text-4xl font-bold text-foreground mb-2">{projectName ?? "Sessions"}</Text>
        <Text className="text-muted text-base">{projectRoot}</Text>
      </View>

      <Surface variant="secondary" className="p-4 rounded-lg mb-4">
        <View className="flex-row items-center justify-between gap-3">
          <Text className="text-foreground font-semibold">
            {tokenQuery.isPending ? "Minting access" : "Relay"}
          </Text>
          <Chip
            variant="secondary"
            color={status === "connected" ? "success" : status === "error" ? "danger" : "default"}
          >
            <Chip.Label>{status.toUpperCase()}</Chip.Label>
          </Chip>
        </View>
        <Text className="text-muted text-sm mt-3">{modelView.label}</Text>
        {modelView.divergence ? (
          <Text className="text-warning text-sm mt-1">{modelView.divergence}</Text>
        ) : null}
        {daemonState.waitingForLock ? (
          <Text className="text-warning text-sm mt-2">
            Waiting on {daemonState.waitingForLock.path} held by{" "}
            {daemonState.waitingForLock.holderAgent}
          </Text>
        ) : null}
      </Surface>

      {error ? <Text className="text-danger text-sm mb-3">{error}</Text> : null}
      {daemonState.draining ? (
        <Surface variant="secondary" className="p-4 rounded-lg mb-3 border border-warning">
          <Text className="text-foreground font-semibold">Daemon draining</Text>
          <Text className="text-muted text-sm mt-1">{daemonState.draining.copy}</Text>
        </Surface>
      ) : null}
      {uiBusy ? <Spinner /> : null}

      <View className="gap-3 mb-5">
        <View className="flex-row items-center justify-between">
          <Text className="text-foreground text-xl font-semibold">Sessions</Text>
          <Button onPress={loadSessions} isDisabled={!client || uiBusy}>
            <Button.Label>Refresh</Button.Label>
          </Button>
        </View>
        {sessions.map((session) => (
          <Card key={session.session_id} variant="secondary" className="p-4">
            <Button
              onPress={() => attach(session.session_id)}
              isDisabled={!client || status !== "connected" || uiBusy}
            >
              <Button.Label>{formatSessionTitle(session)}</Button.Label>
            </Button>
            <Text className="text-muted text-sm mt-2">{sessionActivityLabel(session)}</Text>
          </Card>
        ))}
      </View>

      {selectedSessionId ? (
        <View className="gap-3 mb-3">
          <Text className="text-foreground text-xl font-semibold">Transcript</Text>
          {historyPaging.hasMore ? (
            <View className="gap-2 items-center">
              <Button
                onPress={() => void loadOlderHistory()}
                isDisabled={historyPaging.isLoading || !selectedAttachmentReady}
              >
                <Button.Label>
                  {historyPaging.isLoading
                    ? "Loading older…"
                    : historyPaging.error
                      ? "Retry load older"
                      : "Load older"}
                </Button.Label>
              </Button>
              {historyPaging.error ? (
                <Text className="text-danger text-xs">{historyPaging.error}</Text>
              ) : null}
            </View>
          ) : null}
          {unresolvedInterrupts.map((entry) =>
            entry.kind === "interrupt" ? (
              <InterruptCard
                key={entry.id}
                entry={entry}
                busy={uiBusy || !selectedAttachmentReady}
                draft={
                  interruptDrafts[entry.interrupt.interruptId] ?? { text: "", selectedIds: [] }
                }
                onTextChange={setInterruptText}
                onToggleSelection={toggleInterruptSelection}
                onResolve={resolveInterrupt}
              />
            ) : null,
          )}
        </View>
      ) : null}
    </View>
  );

  const listFooter = selectedSessionId ? (
    <View className="gap-3 p-6 pt-3">
      {daemonState.sandboxNotice ? (
        <Surface variant="secondary" className="p-4 rounded-lg border border-warning">
          <Text className="text-foreground font-semibold">Sandbox unavailable</Text>
          <Text className="text-muted text-sm mt-1">{daemonState.sandboxNotice.remedy}</Text>
          {daemonState.sandboxNotice.fixCommand ? (
            <View className="mt-3 gap-2">
              <Text className="text-foreground text-sm">
                {daemonState.sandboxNotice.fixCommand}
              </Text>
              <Button onPress={copyFixCommand}>
                <Button.Label>Copy fix command</Button.Label>
              </Button>
            </View>
          ) : null}
        </Surface>
      ) : null}

      {daemonState.pausedWork ? (
        <Surface variant="secondary" className="p-4 rounded-lg border border-warning">
          <Text className="text-foreground font-semibold">Paused work available</Text>
          <Text className="text-muted text-sm mt-1">
            {daemonState.pausedWork.items.length} paused item
            {daemonState.pausedWork.items.length === 1 ? "" : "s"} need a decision.
          </Text>
          <View className="flex-row gap-2 mt-3">
            <Button
              onPress={resumePausedWork}
              isDisabled={uiBusy || !attachmentReadyFor(daemonState.pausedWork.sessionId)}
            >
              <Button.Label>Resume</Button.Label>
            </Button>
            <Button
              onPress={cancelPausedWork}
              isDisabled={uiBusy || !attachmentReadyFor(daemonState.pausedWork.sessionId)}
            >
              <Button.Label>Cancel</Button.Label>
            </Button>
          </View>
        </Surface>
      ) : null}

      {daemonState.repairRequired ? (
        <Surface variant="secondary" className="p-4 rounded-lg border border-warning">
          <Text className="text-foreground font-semibold">Read-only recovery</Text>
          <Text className="text-muted text-sm mt-1">{daemonState.repairRequired.detail}</Text>
        </Surface>
      ) : null}

      <Surface variant="secondary" className="p-4 rounded-lg">
        <TextField>
          <Input
            value={message}
            onChangeText={(value) => {
              if (selectedSessionId) {
                setSessionMessage(selectedSessionId, value);
                if (retrySubmission && retrySubmission.params.text !== value.trim()) {
                  setSessionRetry(selectedSessionId, null);
                }
              }
            }}
            placeholder="Message Flycockpit"
            multiline
            isDisabled={sendingMessage || Boolean(daemonState.repairRequired)}
          />
        </TextField>
        <View className="flex-row flex-wrap gap-2 mt-3">
          <Button onPress={pasteClipboard}>
            <Button.Label>Paste</Button.Label>
          </Button>
          <Button onPress={addImage}>
            <Button.Label>Image</Button.Label>
          </Button>
          <Button onPress={sendMessage} isDisabled={sendDisabled}>
            <Button.Label>Send</Button.Label>
          </Button>
        </View>
      </Surface>
    </View>
  ) : (
    <View className="h-6" />
  );

  return (
    <Container isScrollable={transcriptScrollOwners.containerScrollable} className="flex-1">
      <TranscriptList
        ref={transcriptListRef}
        style={{ flex: 1 }}
        data={selectedSessionId ? history : []}
        keyExtractor={(entry) => entry.id}
        renderItem={({ item }) => (
          <View className="px-6 pb-3">
            <TranscriptEntry entry={item} />
          </View>
        )}
        ListHeaderComponent={listHeader}
        ListFooterComponent={listFooter}
        onScroll={onTranscriptScroll}
        onContentSizeChange={onTranscriptContentSizeChange}
        scrollEventThrottle={16}
        keyboardShouldPersistTaps="handled"
        // Single virtualized scroll owner — never nested in Container ScrollView.
        nestedScrollEnabled={transcriptScrollOwners.nestedSameAxisUnboundedScrollView}
      />
    </Container>
  );
}

type InterruptHistoryEntry = Extract<NativeHistoryEntry, { kind: "interrupt" }>;

function InterruptCard({
  entry,
  busy,
  draft,
  onTextChange,
  onToggleSelection,
  onResolve,
}: {
  entry: InterruptHistoryEntry;
  busy: boolean;
  draft: InterruptDraft;
  onTextChange: (interruptId: string, text: string) => void;
  onToggleSelection: (interruptId: string, optionId: string) => void;
  onResolve: (interruptId: string, selection: InterruptSelection) => void;
}) {
  const interruptId = entry.interrupt.interruptId;
  const view = interruptView(entry.interrupt.question);

  return (
    <Surface variant="secondary" className="p-4 rounded-lg border border-warning">
      <Text className="text-warning text-xs mb-1">{entry.interrupt.kind}</Text>
      <Text className="text-foreground font-semibold">{view.prompt}</Text>
      {entry.interrupt.body && !hasCommandDetail(view) ? (
        <Text className="text-muted text-sm mt-2">{entry.interrupt.body}</Text>
      ) : null}

      {view.kind === "single" ? (
        <SingleInterruptControls
          interruptId={interruptId}
          view={view}
          busy={busy}
          draft={draft}
          onTextChange={onTextChange}
          onResolve={onResolve}
        />
      ) : null}

      {view.kind === "multi" ? (
        <MultiInterruptControls
          interruptId={interruptId}
          view={view}
          busy={busy}
          draft={draft}
          onTextChange={onTextChange}
          onToggleSelection={onToggleSelection}
          onResolve={onResolve}
        />
      ) : null}

      {view.kind === "freetext" ? (
        <View className="mt-3 gap-3">
          <TextField>
            <Input
              value={draft.text}
              onChangeText={(text) => onTextChange(interruptId, text)}
              placeholder="Answer"
              secureTextEntry={view.masked}
            />
          </TextField>
          <View className="flex-row flex-wrap gap-2">
            <Button
              onPress={() => onResolve(interruptId, { kind: "freetext", text: draft.text })}
              isDisabled={busy}
            >
              <Button.Label>Answer</Button.Label>
            </Button>
            <Button onPress={() => onResolve(interruptId, { kind: "cancel" })} isDisabled={busy}>
              <Button.Label>Decline</Button.Label>
            </Button>
          </View>
        </View>
      ) : null}
    </Surface>
  );
}

function SingleInterruptControls({
  interruptId,
  view,
  busy,
  draft,
  onTextChange,
  onResolve,
}: {
  interruptId: string;
  view: Extract<InterruptView, { kind: "single" }>;
  busy: boolean;
  draft: InterruptDraft;
  onTextChange: (interruptId: string, text: string) => void;
  onResolve: (interruptId: string, selection: InterruptSelection) => void;
}) {
  return (
    <View className="mt-3 gap-3">
      <CommandDetailBlock view={view} />

      <OptionGroup
        options={view.primaryOptions}
        busy={busy}
        onPress={(option) => onResolve(interruptId, { kind: "single", selectedId: option.id })}
      />

      {view.commandDetail?.scopeOptions.length ? (
        <View className="gap-2">
          <Text className="text-muted text-xs">Grant scope</Text>
          <OptionGroup
            options={view.commandDetail.scopeOptions}
            busy={busy}
            onPress={(option) => onResolve(interruptId, { kind: "single", selectedId: option.id })}
          />
        </View>
      ) : null}

      {view.sandboxEscalation ? <SandboxEscalationBlock view={view} /> : null}

      {view.secondaryOptions.length ? (
        <View className="gap-2">
          <Text className="text-muted text-xs">Additional access</Text>
          <OptionGroup
            options={view.secondaryOptions}
            busy={busy}
            onPress={(option) => onResolve(interruptId, { kind: "single", selectedId: option.id })}
          />
        </View>
      ) : null}

      {view.freeText ? (
        <View className="gap-2">
          <TextField>
            <Input
              value={draft.text}
              onChangeText={(text) => onTextChange(interruptId, text)}
              placeholder="Custom answer"
            />
          </TextField>
          <Button
            onPress={() => onResolve(interruptId, { kind: "freetext", text: draft.text })}
            isDisabled={busy}
          >
            <Button.Label>Answer</Button.Label>
          </Button>
        </View>
      ) : null}

      <Button onPress={() => onResolve(interruptId, { kind: "cancel" })} isDisabled={busy}>
        <Button.Label>Decline</Button.Label>
      </Button>
    </View>
  );
}

function MultiInterruptControls({
  interruptId,
  view,
  busy,
  draft,
  onTextChange,
  onToggleSelection,
  onResolve,
}: {
  interruptId: string;
  view: Extract<InterruptView, { kind: "multi" }>;
  busy: boolean;
  draft: InterruptDraft;
  onTextChange: (interruptId: string, text: string) => void;
  onToggleSelection: (interruptId: string, optionId: string) => void;
  onResolve: (interruptId: string, selection: InterruptSelection) => void;
}) {
  return (
    <View className="mt-3 gap-3">
      <MultiOptionGroup
        options={view.primaryOptions}
        selectedIds={draft.selectedIds}
        busy={busy}
        onToggle={(optionId) => onToggleSelection(interruptId, optionId)}
      />

      {view.secondaryOptions.length ? (
        <View className="gap-2">
          <Text className="text-muted text-xs">Additional choices</Text>
          <MultiOptionGroup
            options={view.secondaryOptions}
            selectedIds={draft.selectedIds}
            busy={busy}
            onToggle={(optionId) => onToggleSelection(interruptId, optionId)}
          />
        </View>
      ) : null}

      {view.freeText ? (
        <TextField>
          <Input
            value={draft.text}
            onChangeText={(text) => onTextChange(interruptId, text)}
            placeholder="Custom answer"
          />
        </TextField>
      ) : null}

      <View className="flex-row flex-wrap gap-2">
        <Button
          onPress={() => onResolve(interruptId, { kind: "multi", selectedIds: draft.selectedIds })}
          isDisabled={busy || draft.selectedIds.length === 0}
        >
          <Button.Label>Submit choices</Button.Label>
        </Button>
        {view.freeText ? (
          <Button
            onPress={() => onResolve(interruptId, { kind: "freetext", text: draft.text })}
            isDisabled={busy}
          >
            <Button.Label>Answer</Button.Label>
          </Button>
        ) : null}
        <Button onPress={() => onResolve(interruptId, { kind: "cancel" })} isDisabled={busy}>
          <Button.Label>Decline</Button.Label>
        </Button>
      </View>
    </View>
  );
}

function MultiOptionGroup({
  options,
  selectedIds,
  busy,
  onToggle,
}: {
  options: InterruptOption[];
  selectedIds: string[];
  busy: boolean;
  onToggle: (optionId: string) => void;
}) {
  if (options.length === 0) return null;
  return (
    <View className="gap-2">
      {options.map((option) => {
        const selected = selectedIds.includes(option.id);
        return (
          <View key={option.id} className="gap-1">
            <Button onPress={() => onToggle(option.id)} isDisabled={busy}>
              <Button.Label>{selected ? `Selected: ${option.label}` : option.label}</Button.Label>
            </Button>
            {option.description ? (
              <Text className="text-muted text-xs">{option.description}</Text>
            ) : null}
          </View>
        );
      })}
    </View>
  );
}

function OptionGroup({
  options,
  busy,
  onPress,
}: {
  options: Array<InterruptOption | { id: string; label: string; description?: string }>;
  busy: boolean;
  onPress: (option: InterruptOption | { id: string; label: string; description?: string }) => void;
}) {
  if (options.length === 0) return null;
  return (
    <View className="gap-2">
      {options.map((option) => (
        <View key={option.id} className="gap-1">
          <Button onPress={() => onPress(option)} isDisabled={busy}>
            <Button.Label>{option.label}</Button.Label>
          </Button>
          {option.description ? (
            <Text className="text-muted text-xs">{option.description}</Text>
          ) : null}
        </View>
      ))}
    </View>
  );
}

function CommandDetailBlock({ view }: { view: Extract<InterruptView, { kind: "single" }> }) {
  const command = view.commandDetail;
  if (!command) return null;

  return (
    <View className="gap-2">
      <View className="flex-row flex-wrap items-center gap-2">
        <Chip variant="secondary" color={riskChipColor(command.risk.tone)}>
          <Chip.Label>{command.risk.label}</Chip.Label>
        </Chip>
        {view.approvalClassLabel ? (
          <Chip variant="secondary" color="default">
            <Chip.Label>{view.approvalClassLabel}</Chip.Label>
          </Chip>
        ) : null}
        <Text className="text-muted text-xs">{command.stepLabel}</Text>
      </View>
      <Text className="text-foreground text-sm">{command.fullCommand}</Text>
      {command.cwd ? <Text className="text-muted text-xs">cwd: {command.cwd}</Text> : null}
      {command.reasons.length ? (
        <Text className="text-muted text-xs">reasons: {command.reasons.join(", ")}</Text>
      ) : null}
      {command.affectedTargets.length ? (
        <Text className="text-muted text-xs">affected: {command.affectedTargets.join(", ")}</Text>
      ) : null}
      {command.policyCap ? (
        <Text className="text-muted text-xs">policy cap: {command.policyCap}</Text>
      ) : null}
      {command.nativeToolHints.length ? (
        <Text className="text-muted text-xs">hints: {command.nativeToolHints.join(", ")}</Text>
      ) : null}
      {command.writeContent ? (
        <Surface variant="secondary" className="p-3 rounded-lg">
          <Text className="text-muted text-xs mb-1">
            write content{command.writeContent.dynamic ? " (dynamic)" : ""}
          </Text>
          <Text className="text-foreground text-xs">
            {command.writeContent.preview}
            {command.writeContent.truncated ? "..." : ""}
          </Text>
        </Surface>
      ) : null}
    </View>
  );
}

function SandboxEscalationBlock({ view }: { view: Extract<InterruptView, { kind: "single" }> }) {
  const escalation = view.sandboxEscalation;
  if (!escalation) return null;

  return (
    <Surface variant="secondary" className="p-3 rounded-lg border border-warning">
      <Text className="text-warning text-xs mb-1">Sandbox escalation</Text>
      <Text className="text-muted text-xs">exit: {escalation.confinedExit}</Text>
      <Text className="text-muted text-xs">
        stderr: {escalation.confinedStderrPreview}
        {escalation.confinedStderrTruncated ? "..." : ""}
      </Text>
      {escalation.suggestedPaths.length ? (
        <Text className="text-muted text-xs">paths: {escalation.suggestedPaths.join(", ")}</Text>
      ) : null}
      {escalation.suggestedAccess ? (
        <Text className="text-muted text-xs">access: {escalation.suggestedAccess}</Text>
      ) : null}
      {escalation.denial ? (
        <Text className="text-muted text-xs">
          denial: {escalation.denial.confidence}, {escalation.denial.evidenceCount} evidence
        </Text>
      ) : null}
    </Surface>
  );
}

function hasCommandDetail(view: InterruptView) {
  return view.kind === "single" && !!view.commandDetail;
}

function riskChipColor(tone: RiskTone): "default" | "success" | "warning" | "danger" {
  if (tone === "low") return "success";
  if (tone === "medium") return "warning";
  if (tone === "high" || tone === "critical") return "danger";
  return "default";
}

function TranscriptEntry({ entry }: { entry: NativeHistoryEntry }) {
  if (entry.kind === "inference_error") {
    return (
      <Surface variant="secondary" className="p-4 rounded-lg border border-danger">
        <Text className="text-danger text-xs mb-1">inference error</Text>
        <Text className="text-foreground font-semibold">{entry.view.headline}</Text>
        <Text className="text-muted text-xs mt-1">{entry.view.errorClass}</Text>
        <Text className="text-muted text-sm mt-1">{entry.view.detail}</Text>
        {entry.view.recovery.kind === "none" ? null : (
          <View className="mt-3 gap-2">
            <Text className="text-foreground text-sm">{entry.view.recovery.label}</Text>
            <Text className="text-muted text-sm">{entry.view.recovery.guidance}</Text>
          </View>
        )}
      </Surface>
    );
  }
  if (entry.kind === "interrupt_decision") {
    const view = interruptDecisionView(entry);
    if (!view) return null;
    return (
      <Surface variant="secondary" className="p-3 rounded-lg">
        <Text className="text-muted text-xs mb-1">interrupt decision</Text>
        <Text className="text-foreground font-semibold">
          {view.cancelled ? "Interrupt cancelled" : "Interrupt resolved"}
        </Text>
        <Text className="text-muted text-xs mt-1">
          {view.permission ? "Permission" : "Question"}
        </Text>
        {view.lines.length ? (
          <View className="mt-3 gap-2">
            {view.lines.map((line, index) => (
              <View key={`${line.prompt}:${index}`} className="gap-1">
                <Text className="text-muted text-xs">{line.prompt}</Text>
                <Text className="text-foreground text-sm">{line.answer}</Text>
              </View>
            ))}
          </View>
        ) : null}
      </Surface>
    );
  }
  return (
    <Surface variant="secondary" className="p-3 rounded-lg">
      <Text className="text-muted text-xs mb-1">{entry.kind.replaceAll("_", " ")}</Text>
      <Text className="text-foreground text-sm">{historyText(entry)}</Text>
    </Surface>
  );
}
