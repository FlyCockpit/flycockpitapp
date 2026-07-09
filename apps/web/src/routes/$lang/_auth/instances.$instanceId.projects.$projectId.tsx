import type { HistoryEntry, SessionSummary } from "@flycockpit/cockpit-protocol";
import { Button } from "@flycockpit/ui/components/button";
import { Card, CardContent, CardHeader, CardTitle } from "@flycockpit/ui/components/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@flycockpit/ui/components/dialog";
import { Input } from "@flycockpit/ui/components/input";
import { Label } from "@flycockpit/ui/components/label";
import { toast } from "@flycockpit/ui/components/sileo";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { Switch } from "@flycockpit/ui/components/switch";
import { Textarea } from "@flycockpit/ui/components/textarea";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  Archive,
  ArrowLeft,
  FileCode,
  GitFork,
  MessageSquarePlus,
  Send,
  ShieldAlert,
  WifiOff,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import ReactMarkdown from "react-markdown";
import { useShallow } from "zustand/react/shallow";
import { InlineRetry } from "@/components/inline-retry";
import { useRemoteInstanceConnection } from "@/hooks/use-remote-instance-connection";
import { useRemoteProjectSessions } from "@/hooks/use-remote-project-sessions";
import {
  canMutateSessions,
  resolveSessionViewerMode,
  type SessionViewerMode,
  sessionAttributionName,
  shouldShowSessionAttribution,
} from "@/lib/session-visibility";
import { useRemoteSessionsStore } from "@/stores/remote-sessions";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_auth/instances/$instanceId/projects/$projectId")({
  validateSearch: (search: Record<string, unknown>) => ({
    session: typeof search.session === "string" ? search.session : undefined,
    interrupt: typeof search.interrupt === "string" ? search.interrupt : undefined,
  }),
  component: ProjectSessionPage,
});

function ProjectSessionPage() {
  const { lang, instanceId, projectId } = Route.useParams();
  const { session } = Route.useRouteContext();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const { t } = useTranslation(["instances", "common"]);
  const {
    data: tokenData,
    error: tokenError,
    isError: tokenIsError,
    isPending: tokenIsPending,
    refetch: refetchToken,
  } = useQuery(orpc.instances.mintClientToken.queryOptions({ input: { instanceId } }));
  const ownedInstances = useQuery(orpc.instances.listMine.queryOptions());
  const sharedInstances = useQuery(orpc.instanceSharing.listSharedWithMe.queryOptions());
  useRemoteInstanceConnection(instanceId, tokenData);
  const { remote, sendMessage, resolveInterrupt, renameSession, archiveSession, forkSession } =
    useRemoteSessionsStore(
      useShallow((state) => ({
        remote: state.instances[instanceId],
        sendMessage: state.sendMessage,
        resolveInterrupt: state.resolveInterrupt,
        renameSession: state.renameSession,
        archiveSession: state.archiveSession,
        forkSession: state.forkSession,
      })),
    );
  const project = remote?.projects.find((item) => item.projectId === projectId);
  const projectRoot = project?.projectRoot ?? decodeURIComponent(projectId);
  const sessions = remote?.sessionsByProject[projectRoot] ?? [];
  const selectedSessionId =
    search.session ??
    sessions.find((session) => !session.archived)?.sessionId ??
    sessions[0]?.sessionId ??
    null;
  useRemoteProjectSessions({
    instanceId,
    projectRoot,
    sessionId: selectedSessionId,
    connected: remote?.status === "connected",
  });
  const detail = selectedSessionId ? remote?.detailsBySession[selectedSessionId] : null;
  const [message, setMessage] = useState("");
  const [renameTitle, setRenameTitle] = useState("");

  const activeSessions = sessions.filter((session) => !session.archived);
  const archivedSessions = sessions.filter((session) => session.archived);
  const viewerMode = resolveSessionViewerMode({
    instanceId,
    projectRoot,
    ownedInstanceIds: ownedInstances.data?.instances.map((item) => item.id) ?? [],
    sharedInstances: sharedInstances.data?.sharedInstances ?? [],
  });
  const canWriteSessions = canMutateSessions(viewerMode);
  const canShareSessions = viewerMode === "owner";
  const readOnly = viewerMode === "agent_readonly";
  const offline = remote?.status !== "connected";

  async function submitMessage() {
    const text = message.trim();
    if (!selectedSessionId || !text || !canWriteSessions) return;
    setMessage("");
    try {
      await sendMessage(instanceId, selectedSessionId, text);
    } catch {
      toast.error(t("instances:remote.sendFailed"));
      setMessage(text);
    }
  }

  if (tokenIsPending) return <ProjectSkeleton />;
  if (tokenIsError) {
    return (
      <InlineRetry
        className="container mx-auto max-w-5xl px-4 py-12"
        message={friendly(tokenError, t("instances:remote.loadProjectFailed"))}
        onRetry={() => refetchToken()}
      />
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="border-b px-4 py-3">
        <div className="mx-auto flex max-w-7xl flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <Link
              to="/$lang/instances/$instanceId"
              params={{ lang, instanceId }}
              className="mb-1 inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="size-4" />
              {t("instances:remote.backToProjects")}
            </Link>
            <h1 className="truncate font-semibold text-lg">
              {project?.displayName ?? projectRoot}
            </h1>
            <p className="truncate text-sm text-muted-foreground">{projectRoot}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link
              to="/$lang/instances/$instanceId/projects/$projectId/files"
              params={{ lang, instanceId, projectId }}
              search={{
                path: undefined,
                file: undefined,
                showHidden: false,
                session: undefined,
                interrupt: undefined,
              }}
              className="inline-flex min-h-[44px] items-center justify-center gap-2 rounded-md border bg-background px-3 py-2 text-sm font-medium hover:bg-accent hover:text-accent-foreground"
            >
              <FileCode className="size-4" />
              {t("instances:files.open")}
            </Link>
            {canWriteSessions ? (
              <NewSessionDialog
                instanceId={instanceId}
                projectRoot={projectRoot}
                onCreated={(sessionId) => {
                  navigate({ search: { session: sessionId, interrupt: undefined } });
                }}
              />
            ) : null}
          </div>
        </div>
      </div>

      {offline ? (
        <div className="border-b bg-muted/40 px-4 py-2 text-sm text-muted-foreground">
          <div className="mx-auto flex max-w-7xl items-center gap-2">
            <WifiOff className="size-4" />
            {t("instances:remote.offlineBanner")}
          </div>
        </div>
      ) : null}

      <div className="mx-auto grid min-h-0 w-full max-w-7xl flex-1 grid-cols-1 md:grid-cols-[18rem_1fr]">
        <aside className="min-h-0 border-b md:border-r md:border-b-0">
          <div className="flex max-h-56 gap-2 overflow-x-auto p-3 md:max-h-none md:flex-col md:overflow-y-auto md:overflow-x-hidden">
            <SessionSection
              title={t("instances:remote.activeSessions")}
              sessions={activeSessions}
              selectedSessionId={selectedSessionId}
              lang={lang}
              instanceId={instanceId}
              projectId={projectId}
              viewerMode={viewerMode}
              viewerUserId={session.user.id}
            />
            {archivedSessions.length ? (
              <SessionSection
                title={t("instances:remote.archivedSessions")}
                sessions={archivedSessions}
                selectedSessionId={selectedSessionId}
                lang={lang}
                instanceId={instanceId}
                projectId={projectId}
                viewerMode={viewerMode}
                viewerUserId={session.user.id}
              />
            ) : null}
          </div>
        </aside>

        <main className="flex min-h-0 flex-col">
          {detail ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-3">
                <div className="min-w-0">
                  <h2 className="truncate font-medium">{detail.summary.title}</h2>
                  <p className="text-xs text-muted-foreground">
                    {t("instances:remote.turns", { count: detail.summary.turnCount })}
                    {detail.usage?.totalTokens
                      ? " · " + detail.usage.totalTokens + " " + t("instances:remote.tokens")
                      : ""}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {canShareSessions ? (
                    <SessionVisibilityToggle
                      instanceId={instanceId}
                      session={detail.summary}
                      disabled={offline || !canWriteSessions}
                    />
                  ) : null}
                  {canWriteSessions ? (
                    <>
                      <form
                        className="flex gap-2"
                        onSubmit={(event) => {
                          event.preventDefault();
                          const title = renameTitle.trim();
                          if (!title) return;
                          setRenameTitle("");
                          void renameSession(instanceId, detail.summary.sessionId, title);
                        }}
                      >
                        <Input
                          className="h-9 w-36 text-sm"
                          value={renameTitle}
                          onChange={(event) => setRenameTitle(event.target.value)}
                          placeholder={t("instances:remote.renamePlaceholder")}
                        />
                        <Button type="submit" variant="outline" size="sm">
                          {t("instances:remote.rename")}
                        </Button>
                      </form>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => void forkSession(instanceId, detail.summary.sessionId)}
                      >
                        <GitFork className="size-4" />
                        {t("instances:remote.fork")}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          void archiveSession(
                            instanceId,
                            detail.summary.sessionId,
                            !detail.summary.archived,
                          )
                        }
                      >
                        <Archive className="size-4" />
                        {detail.summary.archived
                          ? t("instances:remote.unarchive")
                          : t("instances:remote.archive")}
                      </Button>
                    </>
                  ) : null}
                </div>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
                <Transcript
                  history={detail.history}
                  interruptFocus={search.interrupt}
                  readOnly={!canWriteSessions}
                  onResolve={(interruptId, resolution, answer) =>
                    canWriteSessions
                      ? resolveInterrupt(instanceId, {
                          sessionId: detail.summary.sessionId,
                          interruptId,
                          resolution,
                          answer,
                        })
                      : Promise.resolve()
                  }
                />
              </div>
              <div className="border-t p-3 pb-[calc(0.75rem_+_var(--safe-area-bottom))]">
                {readOnly ? (
                  <p className="mb-2 rounded-md border bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
                    {t("instances:remote.readOnlyNotice")}
                  </p>
                ) : null}
                <div className="flex gap-2">
                  <Textarea
                    className="min-h-[52px] flex-1 text-base"
                    value={message}
                    disabled={offline || !canWriteSessions}
                    onChange={(event) => setMessage(event.target.value)}
                    placeholder={
                      offline
                        ? t("instances:remote.composerOffline")
                        : readOnly
                          ? t("instances:remote.composerReadOnly")
                          : t("instances:remote.composerPlaceholder")
                    }
                    onKeyDown={(event) => {
                      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
                        event.preventDefault();
                        void submitMessage();
                      }
                    }}
                  />
                  <Button
                    type="button"
                    className="min-h-[52px]"
                    disabled={offline || !canWriteSessions || !message.trim()}
                    onClick={() => void submitMessage()}
                  >
                    <Send className="size-4" />
                    {t("instances:remote.send")}
                  </Button>
                </div>
              </div>
            </>
          ) : (
            <div className="flex flex-1 items-center justify-center p-8 text-center text-sm text-muted-foreground">
              {sessions.length
                ? t("instances:remote.selectSession")
                : t("instances:remote.noSessions")}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function SessionSection({
  title,
  sessions,
  selectedSessionId,
  lang,
  instanceId,
  projectId,
  viewerMode,
  viewerUserId,
}: {
  title: string;
  sessions: SessionSummary[];
  selectedSessionId: string | null;
  lang: string;
  instanceId: string;
  projectId: string;
  viewerMode: SessionViewerMode;
  viewerUserId?: string;
}) {
  const { t } = useTranslation("instances");
  if (!sessions.length) return null;
  return (
    <section className="min-w-60 space-y-2 md:min-w-0">
      <h3 className="px-2 text-xs font-medium uppercase text-muted-foreground">{title}</h3>
      <div className="space-y-1">
        {sessions.map((session) => (
          <Link
            key={session.sessionId}
            to="/$lang/instances/$instanceId/projects/$projectId"
            params={{ lang, instanceId, projectId }}
            search={{ session: session.sessionId, interrupt: undefined }}
            className={
              "block rounded-md border px-3 py-2 text-sm " +
              (session.sessionId === selectedSessionId
                ? "border-primary bg-primary/10"
                : "hover:bg-muted")
            }
          >
            <div className="flex items-center justify-between gap-2">
              <span className="truncate font-medium">{session.title}</span>
              {session.attention ? <ShieldAlert className="size-4 shrink-0 text-primary" /> : null}
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <span>{session.shortId ?? session.sessionId.slice(0, 8)}</span>
              <span>{session.status}</span>
              {shouldShowSessionAttribution({ session, viewerMode, viewerUserId }) ? (
                <span className="rounded border bg-muted px-1.5 py-0.5 text-[11px] text-foreground">
                  {t("remote.createdBy", {
                    name: sessionAttributionName(session, t("remote.collaborator")),
                  })}
                </span>
              ) : null}
            </div>
          </Link>
        ))}
      </div>
    </section>
  );
}

function Transcript({
  history,
  interruptFocus,
  readOnly,
  onResolve,
}: {
  history: HistoryEntry[];
  interruptFocus?: string;
  readOnly: boolean;
  onResolve: (
    interruptId: string,
    resolution: "approve" | "deny" | "answer",
    answer?: string,
  ) => Promise<void>;
}) {
  return (
    <div className="space-y-3">
      {history.map((entry) => (
        <TranscriptEntry
          key={entry.id}
          entry={entry}
          focused={entry.kind === "interrupt" && entry.interrupt.interruptId === interruptFocus}
          readOnly={readOnly}
          onResolve={onResolve}
        />
      ))}
    </div>
  );
}

function TranscriptEntry({
  entry,
  focused,
  readOnly,
  onResolve,
}: {
  entry: HistoryEntry;
  focused: boolean;
  readOnly: boolean;
  onResolve: (
    interruptId: string,
    resolution: "approve" | "deny" | "answer",
    answer?: string,
  ) => Promise<void>;
}) {
  const { t } = useTranslation("instances");
  if (entry.kind === "user_message")
    return (
      <Bubble label={entry.actor?.displayName ?? t("remote.user")} tone="user" text={entry.text} />
    );
  if (entry.kind === "assistant_text")
    return <Bubble label={t("remote.assistant")} tone="assistant" markdown={entry.text} />;
  if (entry.kind === "assistant_reasoning")
    return (
      <details className="rounded-md border p-3 text-sm">
        <summary>{t("remote.reasoning")}</summary>
        <ReactMarkdown>{entry.text}</ReactMarkdown>
      </details>
    );
  if (entry.kind === "tool_call")
    return (
      <details className="rounded-md border p-3 text-sm">
        <summary>
          {entry.name} · {entry.status}
        </summary>
        <pre className="mt-2 overflow-auto text-xs">
          {JSON.stringify(entry.output ?? entry.input ?? {}, null, 2)}
        </pre>
      </details>
    );
  if (entry.kind === "interrupt") {
    return (
      <Card className={focused ? "border-primary" : ""}>
        <CardHeader>
          <CardTitle className="text-base">{entry.interrupt.title}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {entry.interrupt.body ? (
            <p className="text-sm text-muted-foreground">{entry.interrupt.body}</p>
          ) : null}
          {entry.interrupt.resolved ? (
            <p className="text-sm text-muted-foreground">{t("remote.interruptResolved")}</p>
          ) : readOnly ? (
            <p className="text-sm text-muted-foreground">{t("remote.readOnlyInterruptNotice")}</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                onClick={() => void onResolve(entry.interrupt.interruptId, "approve")}
              >
                {t("remote.approve")}
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => void onResolve(entry.interrupt.interruptId, "deny")}
              >
                {t("remote.deny")}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    );
  }
  return <div className="rounded-md border p-3 text-sm text-muted-foreground">{entry.kind}</div>;
}

function Bubble({
  label,
  tone,
  text,
  markdown,
}: {
  label: string;
  tone: "user" | "assistant";
  text?: string;
  markdown?: string;
}) {
  return (
    <div
      className={
        tone === "user"
          ? "ml-auto max-w-3xl rounded-md bg-primary/10 p-3"
          : "max-w-3xl rounded-md border p-3"
      }
    >
      <div className="mb-1 text-xs font-medium text-muted-foreground">{label}</div>
      {markdown ? (
        <ReactMarkdown>{markdown}</ReactMarkdown>
      ) : (
        <p className="whitespace-pre-wrap text-sm">{text}</p>
      )}
    </div>
  );
}

function SessionVisibilityToggle({
  instanceId,
  session,
  disabled,
}: {
  instanceId: string;
  session: SessionSummary;
  disabled: boolean;
}) {
  const { t } = useTranslation("instances");
  const shareSession = useRemoteSessionsStore((state) => state.shareSession);
  const [pending, setPending] = useState(false);

  async function toggle(shared: boolean) {
    setPending(true);
    try {
      await shareSession(instanceId, session.sessionId, shared);
    } catch {
      toast.error(t("remote.shareSessionFailed"));
    } finally {
      setPending(false);
    }
  }

  return (
    <label className="flex min-h-9 items-center gap-2 rounded-md border px-2 py-1.5 text-sm">
      <span className="leading-tight">
        <span className="block font-medium">{t("remote.visibleToCollaborators")}</span>
        <span className="block text-xs text-muted-foreground">
          {t("remote.visibleToCollaboratorsDescription")}
        </span>
      </span>
      <Switch
        size="sm"
        checked={session.sharedWithCollaborators}
        disabled={disabled || pending}
        onCheckedChange={(checked) => void toggle(checked === true)}
        aria-label={t("remote.visibleToCollaborators")}
      />
    </label>
  );
}

function NewSessionDialog({
  instanceId,
  projectRoot,
  onCreated,
}: {
  instanceId: string;
  projectRoot: string;
  onCreated: (sessionId: string) => void;
}) {
  const { t } = useTranslation("instances");
  const createSession = useRemoteSessionsStore((state) => state.createSession);
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [agent, setAgent] = useState("codex");
  const [model, setModel] = useState("");

  async function submit() {
    try {
      const result = await createSession(instanceId, {
        projectRoot,
        title: title || undefined,
        agent,
        model: model || undefined,
      });
      setOpen(false);
      setTitle("");
      onCreated(result.session.sessionId);
    } catch {
      toast.error(t("remote.createFailed"));
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger
        render={
          <Button className="min-h-[44px]">
            <MessageSquarePlus className="size-4" />
            {t("remote.newSession")}
          </Button>
        }
      />
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("remote.newSession")}</DialogTitle>
          <DialogDescription>{t("remote.newSessionDescription")}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label>{t("remote.sessionTitle")}</Label>
            <Input value={title} onChange={(event) => setTitle(event.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>{t("remote.agent")}</Label>
            <Input value={agent} onChange={(event) => setAgent(event.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>{t("remote.model")}</Label>
            <Input value={model} onChange={(event) => setModel(event.target.value)} />
          </div>
          <Button type="button" className="w-full" onClick={() => void submit()}>
            {t("remote.createSession")}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function ProjectSkeleton() {
  return (
    <div className="container mx-auto max-w-5xl px-4 py-8">
      <Skeleton className="h-[60vh] rounded-lg" />
    </div>
  );
}
