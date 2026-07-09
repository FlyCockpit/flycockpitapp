import {
  type HistoryEntry,
  type LiveEvent,
  liveEventSchema,
  type SessionSummary,
} from "@flycockpit/cockpit-protocol";
import * as Clipboard from "expo-clipboard";
import * as ImagePicker from "expo-image-picker";
import { useLocalSearchParams } from "expo-router";
import { Button, Card, Chip, Input, Spinner, Surface, TextField } from "heroui-native";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Text, View } from "react-native";
import { Container } from "@/components/container";
import { useNativeRemoteClient } from "@/hooks/use-native-remote-client";

function formatSessionTitle(session: SessionSummary) {
  return session.title || session.shortId || session.sessionId;
}

function sortHistory(history: HistoryEntry[]) {
  return [...history].sort((a, b) => a.seq - b.seq || a.id.localeCompare(b.id));
}

function upsertHistory(history: HistoryEntry[], entry: HistoryEntry) {
  return sortHistory([entry, ...history.filter((item) => item.id !== entry.id)]);
}

function applySessionEvent(history: HistoryEntry[], event: LiveEvent) {
  if (event.type === "history_entry") return upsertHistory(history, event.entry);
  if (event.type === "assistant_delta") {
    return history.map((entry) =>
      entry.id === event.entryId && entry.kind === "assistant_text"
        ? { ...entry, text: entry.text + event.delta }
        : entry,
    );
  }
  if (event.type === "interrupt_resolved") {
    return history.map((entry) =>
      entry.kind === "interrupt" && entry.interrupt.interruptId === event.interruptId
        ? { ...entry, interrupt: { ...entry.interrupt, resolved: true } }
        : entry,
    );
  }
  return history;
}

function historyText(entry: HistoryEntry) {
  if (entry.kind === "user_message") return entry.text;
  if (entry.kind === "assistant_text") return entry.text;
  if (entry.kind === "assistant_reasoning") return entry.text;
  if (entry.kind === "tool_call") return entry.name + " " + entry.status;
  if (entry.kind === "inference_error") return entry.message;
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
  const initialSession = Array.isArray(params.session) ? params.session[0] : params.session;
  const projectName = Array.isArray(params.name) ? params.name[0] : params.name;
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(initialSession ?? null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [message, setMessage] = useState("");
  const [answer, setAnswer] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const selectedSessionRef = useRef<string | null>(initialSession ?? null);

  const handleLiveEvent = useCallback((raw: unknown) => {
    const parsed = liveEventSchema.safeParse(raw);
    if (!parsed.success) return;
    const event = parsed.data;
    if (event.type === "session_updated") {
      setSessions((current) =>
        [
          event.summary,
          ...current.filter((session) => session.sessionId !== event.summary.sessionId),
        ].sort((a, b) => b.updatedAt - a.updatedAt),
      );
      return;
    }
    const sessionId = "sessionId" in event ? event.sessionId : null;
    if (!sessionId || sessionId !== selectedSessionRef.current) return;
    setHistory((current) => applySessionEvent(current, event));
  }, []);

  const { client, status, tokenQuery } = useNativeRemoteClient(instanceId, handleLiveEvent);

  useEffect(() => {
    selectedSessionRef.current = selectedSessionId;
  }, [selectedSessionId]);

  const unresolvedInterrupts = useMemo(
    () => history.filter((entry) => entry.kind === "interrupt" && !entry.interrupt.resolved),
    [history],
  );

  const loadSessions = async () => {
    if (!client) return;
    setBusy(true);
    setError(null);
    try {
      const result = await client.listSessions(projectRoot);
      setSessions(result.sessions);
      const nextSession = selectedSessionId ?? result.sessions[0]?.sessionId ?? null;
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
      const result = await client.attach(sessionId);
      setSelectedSessionId(sessionId);
      setHistory(result.history);
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
    try {
      await client.sendUserMessage(selectedSessionId, text, "native-" + Date.now());
    } catch (sendError) {
      setError(sendError instanceof Error ? sendError.message : "Could not send message.");
      setMessage(text);
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

  const resolveInterrupt = async (
    interruptId: string,
    resolution: "approve" | "deny" | "answer",
  ) => {
    if (!client || !selectedSessionId) return;
    setBusy(true);
    setError(null);
    try {
      await client.resolveInterrupt({
        sessionId: selectedSessionId,
        interruptId,
        resolution,
        answer: resolution === "answer" ? answer : undefined,
      });
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
      </Surface>

      {error ? <Text className="text-danger text-sm mb-3">{error}</Text> : null}
      {busy ? <Spinner /> : null}

      <View className="gap-3 mb-5">
        <View className="flex-row items-center justify-between">
          <Text className="text-foreground text-xl font-semibold">Sessions</Text>
          <Button onPress={loadSessions} isDisabled={!client || busy}>
            <Button.Label>Refresh</Button.Label>
          </Button>
        </View>
        {sessions.map((session) => (
          <Card key={session.sessionId} variant="secondary" className="p-4">
            <Button onPress={() => attach(session.sessionId)}>
              <Button.Label>{formatSessionTitle(session)}</Button.Label>
            </Button>
            <Text className="text-muted text-sm mt-2">{session.status.replaceAll("_", " ")}</Text>
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
            <Surface key={entry.id} variant="secondary" className="p-3 rounded-lg">
              <Text className="text-muted text-xs mb-1">{entry.kind.replaceAll("_", " ")}</Text>
              <Text className="text-foreground text-sm">{historyText(entry)}</Text>
            </Surface>
          ))}

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
              <Button onPress={sendMessage} isDisabled={!message.trim() || busy}>
                <Button.Label>Send</Button.Label>
              </Button>
            </View>
          </Surface>
        </View>
      ) : null}
    </Container>
  );
}
