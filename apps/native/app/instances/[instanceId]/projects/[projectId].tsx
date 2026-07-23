import type { HistoryEntry, SessionSummary } from "@flycockpit/cockpit-protocol";
import * as Clipboard from "expo-clipboard";
import * as ImagePicker from "expo-image-picker";
import { useLocalSearchParams } from "expo-router";
import { Button, Card, Chip, Input, Spinner, Surface, TextField } from "heroui-native";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Text, View } from "react-native";
import { Container } from "@/components/container";
import { useNativeRemoteClient } from "@/hooks/use-native-remote-client";
import {
  cancelPausedWorkAction,
  composerSendDisabled,
  emptyNativeDaemonState,
  resumePausedWorkAction,
} from "@/utils/daemon-state";
import { activeModelView } from "@/utils/inference-failure-view";
import {
  appendOptimisticUserMessage,
  type InterruptResolutionAction,
  type NativeHistoryEntry,
  nativeAttachRuntimeState,
  reduceNativeSessionEvent,
  removeOptimisticUserMessage,
  resolveResponseForInterrupt,
  toNativeHistoryEntry,
  warnNativeSessionEvent,
} from "@/utils/session-events";

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
  const [message, setMessage] = useState("");
  const [answer, setAnswer] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [daemonState, setDaemonState] = useState(emptyNativeDaemonState);
  const [activeModel, setActiveModel] = useState<ReturnType<typeof activeModelView> | null>(null);
  const [llmMode, setLlmMode] = useState<string | null>(null);
  const selectedSessionRef = useRef<string | null>(initialSession ?? null);
  const historyRef = useRef<NativeHistoryEntry[]>([]);
  const daemonStateRef = useRef(emptyNativeDaemonState);
  const activeModelStateRef = useRef<Parameters<typeof activeModelView>[0]>(null);
  const llmModeRef = useRef<string | null>(null);
  const optimisticMessageCounterRef = useRef(0);

  const handleSessionEvent = useCallback((raw: unknown) => {
    const result = reduceNativeSessionEvent(
      {
        history: historyRef.current,
        selectedSessionId: selectedSessionRef.current,
        daemonState: daemonStateRef.current,
        activeModel: activeModelStateRef.current,
        llmMode: llmModeRef.current,
      },
      raw,
    );
    warnNativeSessionEvent(result);
    historyRef.current = result.state.history;
    daemonStateRef.current = result.state.daemonState ?? emptyNativeDaemonState;
    activeModelStateRef.current = result.state.activeModel ?? null;
    llmModeRef.current = result.state.llmMode ?? null;
    setHistory(result.state.history);
    setDaemonState(daemonStateRef.current);
    setActiveModel(activeModelView(activeModelStateRef.current, llmModeRef.current));
    setLlmMode(llmModeRef.current);
  }, []);

  const { client, status, tokenQuery } = useNativeRemoteClient(instanceId, handleSessionEvent);

  useEffect(() => {
    selectedSessionRef.current = selectedSessionId;
  }, [selectedSessionId]);

  const unresolvedInterrupts = useMemo(
    () => history.filter((entry) => entry.kind === "interrupt" && !entry.interrupt.resolved),
    [history],
  );
  const modelView = activeModel ?? activeModelView(activeModelStateRef.current, llmMode);
  const sendDisabled = composerSendDisabled({
    message,
    busy,
    draining: daemonState.draining,
  });

  const loadSessions = async () => {
    if (!client) return;
    setBusy(true);
    setError(null);
    try {
      const result = await client.listSessions({ project_id: projectId });
      setSessions(result.sessions);
      const nextSession = selectedSessionId ?? result.sessions[0]?.session_id ?? null;
      setSelectedSessionId(nextSession);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Could not load sessions.");
    } finally {
      setBusy(false);
    }
  };

  const attach = async (sessionId: string) => {
    if (!client) return;
    setBusy(true);
    setError(null);
    try {
      const result = await client.attach({ session_id: sessionId, interactive: true });
      setSelectedSessionId(sessionId);
      selectedSessionRef.current = sessionId;
      const nextHistory = result.history.map((entry: HistoryEntry, index: number) =>
        toNativeHistoryEntry(entry, index),
      );
      const runtime = nativeAttachRuntimeState(result, daemonStateRef.current);
      historyRef.current = nextHistory;
      daemonStateRef.current = runtime.daemonState;
      activeModelStateRef.current = runtime.activeModel;
      llmModeRef.current = runtime.llmMode;
      setHistory(nextHistory);
      setDaemonState(runtime.daemonState);
      setActiveModel(activeModelView(runtime.activeModel, runtime.llmMode));
      setLlmMode(runtime.llmMode);
    } catch (attachError) {
      setError(attachError instanceof Error ? attachError.message : "Could not attach session.");
    } finally {
      setBusy(false);
    }
  };

  const sendMessage = async () => {
    if (!client || !selectedSessionId || !message.trim()) return;
    const text = message.trim();
    setMessage("");
    optimisticMessageCounterRef.current += 1;
    const optimisticId = String(optimisticMessageCounterRef.current);
    const nextHistory = appendOptimisticUserMessage(historyRef.current, text, optimisticId);
    historyRef.current = nextHistory;
    setHistory(nextHistory);
    try {
      await client.sendUserMessage({ text });
    } catch (sendError) {
      setError(sendError instanceof Error ? sendError.message : "Could not send message.");
      setMessage(text);
      const historyWithoutOptimistic = removeOptimisticUserMessage(
        historyRef.current,
        optimisticId,
      );
      historyRef.current = historyWithoutOptimistic;
      setHistory(historyWithoutOptimistic);
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
    if (text) setMessage((current) => (current ? current + "\n" : "") + text);
  };

  const copyFixCommand = async () => {
    const command = daemonState.sandboxNotice?.fixCommand;
    if (command) await Clipboard.setStringAsync(command);
  };

  const resumePausedWork = async () => {
    if (!client || !daemonState.pausedWork) return;
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
    if (!client || !daemonState.pausedWork) return;
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

  const resolveInterrupt = async (interruptId: string, resolution: InterruptResolutionAction) => {
    if (!client || !selectedSessionId) return;
    const interrupt = unresolvedInterrupts.find(
      (entry) => entry.kind === "interrupt" && entry.interrupt.interruptId === interruptId,
    );
    if (interrupt?.kind !== "interrupt") return;
    setBusy(true);
    setError(null);
    try {
      await client.resolveInterrupt(
        interruptId,
        resolveResponseForInterrupt(interrupt.interrupt.question, resolution, answer),
      );
      setAnswer("");
    } catch (resolveError) {
      setError(
        resolveError instanceof Error ? resolveError.message : "Could not resolve interrupt.",
      );
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (status === "connected" && sessions.length === 0) loadSessions();
  }, [status, sessions.length]);

  useEffect(() => {
    if (status === "connected" && selectedSessionId && history.length === 0)
      attach(selectedSessionId);
  }, [status, selectedSessionId, history.length]);

  return (
    <Container className="p-6">
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
      {busy ? <Spinner /> : null}

      <View className="gap-3 mb-5">
        <View className="flex-row items-center justify-between">
          <Text className="text-foreground text-xl font-semibold">Sessions</Text>
          <Button onPress={loadSessions} isDisabled={!client || busy}>
            <Button.Label>Refresh</Button.Label>
          </Button>
        </View>
        {sessions.map((session) => (
          <Card key={session.session_id} variant="secondary" className="p-4">
            <Button onPress={() => attach(session.session_id)}>
              <Button.Label>{formatSessionTitle(session)}</Button.Label>
            </Button>
            <Text className="text-muted text-sm mt-2">{sessionActivityLabel(session)}</Text>
          </Card>
        ))}
      </View>

      {selectedSessionId ? (
        <View className="gap-3">
          <Text className="text-foreground text-xl font-semibold">Transcript</Text>
          {unresolvedInterrupts.map((entry) =>
            entry.kind === "interrupt" ? (
              <Surface
                key={entry.id}
                variant="secondary"
                className="p-4 rounded-lg border border-warning"
              >
                <Text className="text-foreground font-semibold">{entry.interrupt.title}</Text>
                {entry.interrupt.body ? (
                  <Text className="text-muted text-sm mt-2">{entry.interrupt.body}</Text>
                ) : null}
                {entry.interrupt.kind === "question" ? (
                  <TextField className="mt-3">
                    <Input value={answer} onChangeText={setAnswer} placeholder="Answer" />
                  </TextField>
                ) : null}
                <View className="flex-row gap-2 mt-3">
                  {entry.interrupt.kind === "approval" ? (
                    <>
                      <Button
                        onPress={() => resolveInterrupt(entry.interrupt.interruptId, "approve")}
                      >
                        <Button.Label>Approve</Button.Label>
                      </Button>
                      <Button onPress={() => resolveInterrupt(entry.interrupt.interruptId, "deny")}>
                        <Button.Label>Deny</Button.Label>
                      </Button>
                    </>
                  ) : (
                    <Button onPress={() => resolveInterrupt(entry.interrupt.interruptId, "answer")}>
                      <Button.Label>Answer</Button.Label>
                    </Button>
                  )}
                </View>
              </Surface>
            ) : null,
          )}

          {history.map((entry) => (
            <TranscriptEntry key={entry.id} entry={entry} />
          ))}

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
                <Button onPress={resumePausedWork} isDisabled={busy}>
                  <Button.Label>Resume</Button.Label>
                </Button>
                <Button onPress={cancelPausedWork} isDisabled={busy}>
                  <Button.Label>Cancel</Button.Label>
                </Button>
              </View>
            </Surface>
          ) : null}

          <Surface variant="secondary" className="p-4 rounded-lg">
            <TextField>
              <Input
                value={message}
                onChangeText={setMessage}
                placeholder="Message Flycockpit"
                multiline
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
      ) : null}
    </Container>
  );
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
  return (
    <Surface variant="secondary" className="p-3 rounded-lg">
      <Text className="text-muted text-xs mb-1">{entry.kind.replaceAll("_", " ")}</Text>
      <Text className="text-foreground text-sm">{historyText(entry)}</Text>
    </Surface>
  );
}
