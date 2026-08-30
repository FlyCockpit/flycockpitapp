import { createClientSubmissionId } from "@flycockpit/cockpit-protocol";
import { shouldRetainUserMessageSubmission } from "@flycockpit/cockpit-protocol/client";
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
  AlertTriangle,
  Archive,
  ArrowLeft,
  Clipboard,
  FileCode,
  GitFork,
  LoaderCircle,
  MessageSquarePlus,
  PauseCircle,
  Send,
  ShieldAlert,
  WifiOff,
} from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import ReactMarkdown from "react-markdown";
import { useShallow } from "zustand/react/shallow";
import { InlineRetry } from "@/components/inline-retry";
import { useRemoteInstanceConnection } from "@/hooks/use-remote-instance-connection";
import { useRemoteProjectSessions } from "@/hooks/use-remote-project-sessions";
import { useTranscriptHistoryPaging } from "@/hooks/use-transcript-history-paging";
import {
  type InterruptSelection,
  type InterruptView,
  interruptView,
  type RiskVariant,
} from "@/lib/interrupt-view";
import {
  canMutateSessions,
  resolveSessionViewerMode,
  type SessionViewerMode,
  sessionAttributionName,
  shouldShowSessionAttribution,
} from "@/lib/session-visibility";
import { statsRollupToView } from "@/lib/stats-rollup-view";
import {
  isCurrentWebComposerAttempt,
  isWebAttachmentReady,
  type SessionDetail,
  type SessionPagingState,
  useRemoteSessionsStore,
  type WebComposerRetrySubmission,
  type WebHistoryEntry,
  WebSessionCreatedWithSetupError,
  type WebSessionSummary,
} from "@/stores/remote-sessions";
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
  const {
    remote,
    attach,
    sendMessage,
    resolveInterrupt,
    renameSession,
    archiveSession,
    forkSession,
    loadOlderHistory,
    resumePausedWork,
    cancelPausedWork,
  } = useRemoteSessionsStore(
    useShallow((state) => ({
      remote: state.instances[instanceId],
      attach: state.attach,
      sendMessage: state.sendMessage,
      resolveInterrupt: state.resolveInterrupt,
      renameSession: state.renameSession,
      archiveSession: state.archiveSession,
      forkSession: state.forkSession,
      loadOlderHistory: state.loadOlderHistory,
      resumePausedWork: state.resumePausedWork,
      cancelPausedWork: state.cancelPausedWork,
    })),
  );
  const project = remote?.projects.find((item) => item.projectId === projectId);
  const projectRoot = project?.projectRoot ?? projectRootFromRouteParam(projectId);
  const sessions = projectRoot ? (remote?.sessionsByProject[projectRoot] ?? []) : [];
  const selectedSessionId =
    search.session ??
    sessions.find((session) => !session.archived)?.sessionId ??
    sessions[0]?.sessionId ??
    null;
  useRemoteProjectSessions({
    instanceId,
    projectId,
    projectRoot,
    sessionId: selectedSessionId,
    connected: remote?.status === "connected",
  });
  const detail = selectedSessionId ? remote?.detailsBySession[selectedSessionId] : null;
  const statsView = statsRollupToView(
    remote?.statsRollupByProject[projectId],
    detail?.usage?.totalTokens,
  );
  const [messagesBySession, setMessagesBySession] = useState<Record<string, string>>({});
  const [sendingMessage, setSendingMessage] = useState(false);
  const [retrySubmissionsBySession, setRetrySubmissionsBySession] = useState<
    Record<string, WebComposerRetrySubmission | undefined>
  >({});
  const latestSubmitAttempt = useRef(0);
  const selectedSessionIdRef = useRef(selectedSessionId);
  selectedSessionIdRef.current = selectedSessionId;
  const message = selectedSessionId ? (messagesBySession[selectedSessionId] ?? "") : "";
  const retryCandidate = selectedSessionId
    ? retrySubmissionsBySession[selectedSessionId]
    : undefined;
  const retrySubmission =
    retryCandidate &&
    !detail?.history.some(
      (entry) =>
        entry.kind === "user_message" &&
        entry.clientSubmissionIds?.includes(retryCandidate.params.client_submission_id),
    )
      ? retryCandidate
      : undefined;
  const setSessionMessage = (sessionId: string, value: string | ((current: string) => string)) => {
    setMessagesBySession((current) => {
      const previous = current[sessionId] ?? "";
      const next = typeof value === "function" ? value(previous) : value;
      return { ...current, [sessionId]: next };
    });
  };
  const setSessionRetry = (sessionId: string, submission: WebComposerRetrySubmission | null) => {
    setRetrySubmissionsBySession((current) => ({
      ...current,
      [sessionId]: submission ?? undefined,
    }));
  };
  const [renameTitle, setRenameTitle] = useState("");
  const loadOlderSelectedHistory = useCallback(
    () => (selectedSessionId ? loadOlderHistory(instanceId, selectedSessionId) : Promise.resolve()),
    [instanceId, loadOlderHistory, selectedSessionId],
  );
  const transcriptPaging = useTranscriptHistoryPaging({
    anchorKey: selectedSessionId,
    hasMore: detail?.paging.hasMore ?? false,
    isLoading: detail?.paging.isLoading ?? false,
    onLoadOlder: loadOlderSelectedHistory,
  });

  const activeSessions = sessions.filter((session) => !session.archived);
  const archivedSessions = sessions.filter((session) => session.archived);
  const viewerMode = resolveSessionViewerMode({
    instanceId,
    projectRoot: projectRoot ?? "",
    ownedInstanceIds: ownedInstances.data?.instances.map((item) => item.id) ?? [],
    sharedInstances: sharedInstances.data?.sharedInstances ?? [],
  });
  const canWriteSessions = canMutateSessions(viewerMode);
  const canShareSessions = viewerMode === "owner";
  const readOnly = viewerMode === "agent_readonly";
  const offline = remote?.status !== "connected";
  const attachmentReady = isWebAttachmentReady(remote, selectedSessionId);
  const attachmentFailure =
    remote?.attachment.phase === "failed" && remote.attachment.sessionId === selectedSessionId
      ? remote.attachment
      : null;
  const draining = remote?.draining ?? null;
  const repairRequired = detail?.repairRequired;
  const composerDisabled =
    offline ||
    !attachmentReady ||
    !!draining ||
    !canWriteSessions ||
    Boolean(repairRequired) ||
    sendingMessage;

  async function submitMessage() {
    const text = message.trim();
    if (!selectedSessionId || !text || composerDisabled) return;
    const sessionId = selectedSessionId;
    const attempt = ++latestSubmitAttempt.current;
    const submission = (retrySubmission?.sessionId === sessionId &&
    retrySubmission.params.text === text
      ? retrySubmission.params
      : undefined) ?? {
      client_submission_id: createClientSubmissionId(),
      text,
    };
    setSessionMessage(sessionId, "");
    setSendingMessage(true);
    try {
      await sendMessage(instanceId, sessionId, submission);
      // A queue response is only an in-memory daemon acknowledgment. Keep an
      // exact retry candidate until a durable history receipt proves that this
      // UUID was recorded.
    } catch (error) {
      const currentAttempt = isCurrentWebComposerAttempt({
        currentSessionId: selectedSessionIdRef.current,
        attemptedSessionId: sessionId,
        latestAttempt: latestSubmitAttempt.current,
        attempt,
      });
      if (currentAttempt) {
        toast.error(t("instances:remote.sendFailed"));
      }
      // Restore and retain against the attempted session even if the user
      // switched elsewhere before the transport outcome arrived.
      setSessionMessage(sessionId, (current) => current || text);
      setSessionRetry(
        sessionId,
        shouldRetainUserMessageSubmission(error) ? { sessionId, params: submission } : null,
      );
    } finally {
      setSendingMessage(false);
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
              {project?.displayName ?? projectRoot ?? projectId}
            </h1>
            <p className="truncate text-sm text-muted-foreground">{projectRoot ?? projectId}</p>
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
            {canWriteSessions && projectRoot ? (
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

      {offline || draining ? (
        <div className="border-b bg-muted/40 px-4 py-2 text-sm text-muted-foreground">
          <div className="mx-auto flex max-w-7xl items-center gap-2">
            {draining ? <LoaderCircle className="size-4" /> : <WifiOff className="size-4" />}
            {draining
              ? draining.forced
                ? t("instances:remote.daemonDrainingForced")
                : t("instances:remote.daemonDrainingGraceful")
              : t("instances:remote.offlineBanner")}
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
          {attachmentFailure ? (
            <div className="flex items-start justify-between gap-3 border-b bg-destructive/5 px-4 py-3 text-sm">
              <div className="flex min-w-0 items-start gap-2">
                <AlertTriangle className="mt-0.5 size-4 shrink-0 text-destructive" />
                <div className="min-w-0">
                  <div className="font-medium">{t("instances:remote.attachmentFailed")}</div>
                  {attachmentFailure.error ? (
                    <p className="truncate text-muted-foreground">{attachmentFailure.error}</p>
                  ) : null}
                </div>
              </div>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => {
                  if (selectedSessionId) void attach(instanceId, selectedSessionId);
                }}
              >
                {t("instances:remote.retryAttachment")}
              </Button>
            </div>
          ) : null}
          {detail ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-3">
                <div className="min-w-0">
                  <h2 className="truncate font-medium">{detail.summary.title}</h2>
                  <SessionStatsSummary
                    turns={detail.summary.turnCount}
                    statsView={statsView}
                    activeModel={detail.activeModel}
                  />
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
              <div
                ref={transcriptPaging.containerRef}
                className="min-h-0 flex-1 overflow-y-auto px-4 py-4"
                onScroll={transcriptPaging.onScroll}
              >
                <Transcript
                  history={detail.history}
                  paging={detail.paging}
                  onLoadOlder={transcriptPaging.loadOlderWithAnchor}
                  interruptFocus={search.interrupt}
                  readOnly={!canWriteSessions || !attachmentReady || Boolean(repairRequired)}
                  onResolve={(interruptId, selection) =>
                    canWriteSessions && attachmentReady && !repairRequired
                      ? resolveInterrupt(instanceId, {
                          sessionId: detail.summary.sessionId,
                          interruptId,
                          selection,
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
                <SessionStateNotices
                  detail={detail}
                  actionsDisabled={composerDisabled}
                  onResume={() => resumePausedWork(instanceId, detail.summary.sessionId)}
                  onCancel={() => cancelPausedWork(instanceId, detail.summary.sessionId)}
                />
                <div className="flex gap-2">
                  <Textarea
                    className="min-h-[52px] flex-1 text-base"
                    value={message}
                    disabled={composerDisabled}
                    onChange={(event) => {
                      const value = event.target.value;
                      if (selectedSessionId) {
                        setSessionMessage(selectedSessionId, value);
                        if (retrySubmission && retrySubmission.params.text !== value.trim()) {
                          setSessionRetry(selectedSessionId, null);
                        }
                      }
                    }}
                    placeholder={
                      offline
                        ? t("instances:remote.composerOffline")
                        : draining
                          ? t("instances:remote.composerDraining")
                          : readOnly || repairRequired
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
                    disabled={composerDisabled || !message.trim()}
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

function SessionStatsSummary({
  turns,
  statsView,
  activeModel,
}: {
  turns: number;
  statsView: ReturnType<typeof statsRollupToView>;
  activeModel: SessionDetail["activeModel"];
}) {
  const { t } = useTranslation("instances");
  const tokenRows = statsView.tokenRows.slice(0, 2);
  const activeModelLabel = activeModel ? `${activeModel.provider}/${activeModel.model}` : undefined;
  const requestedModelLabel =
    activeModel?.configProvider && activeModel.configModel
      ? `${activeModel.configProvider}/${activeModel.configModel}`
      : undefined;
  return (
    <div className="text-xs text-muted-foreground">
      <span>{t("instances:remote.turns", { count: turns })}</span>
      {activeModelLabel ? (
        <span>
          {" · "}
          {t("instances:remote.activeModelLabel")}: {activeModelLabel}
        </span>
      ) : null}
      {activeModel?.diverged ? (
        <span className="text-amber-700 dark:text-amber-300">
          {" · "}
          {t("instances:remote.activeModelDiverged", {
            model: requestedModelLabel ?? t("instances:remote.configuredModel"),
          })}
        </span>
      ) : null}
      {statsView.fallbackTotal ? (
        <span>
          {" · "}
          {statsView.fallbackTotal} {t("instances:remote.tokens")}
        </span>
      ) : null}
      {tokenRows.length ? (
        <span>
          {" · "}
          {t("instances:remote.statsModels")}:{" "}
          {tokenRows.map((row) => `${row.label} ${row.value}`).join(", ")}
        </span>
      ) : null}
    </div>
  );
}

function SessionStateNotices({
  detail,
  actionsDisabled,
  onResume,
  onCancel,
}: {
  detail: SessionDetail;
  actionsDisabled: boolean;
  onResume: () => Promise<void>;
  onCancel: () => Promise<void>;
}) {
  const { t } = useTranslation("instances");
  const waitingLocks = Object.values(detail.waitingLocks);
  const pausedItems = detail.pausedWork?.items ?? [];
  const hasNotices =
    detail.repairRequired || detail.sandboxUnavailable || waitingLocks.length || pausedItems.length;
  if (!hasNotices) return null;

  async function copyFixCommand(command: string) {
    try {
      await navigator.clipboard.writeText(command);
      toast.success(t("remote.fixCommandCopied"));
    } catch {
      toast.error(t("remote.fixCommandCopyFailed"));
    }
  }

  async function runPausedAction(action: () => Promise<void>) {
    try {
      await action();
    } catch {
      toast.error(t("remote.pausedWorkActionFailed"));
    }
  }

  return (
    <div className="mb-2 space-y-2">
      {detail.repairRequired ? (
        <div className="flex items-start gap-2 rounded-md border bg-muted/40 px-3 py-2 text-sm">
          <ShieldAlert className="mt-0.5 size-4 shrink-0 text-amber-600" />
          <p className="text-muted-foreground">{detail.repairRequired.detail}</p>
        </div>
      ) : null}
      {detail.sandboxUnavailable ? (
        <div className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
          <div className="flex items-start gap-2">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-amber-600" />
            <div className="min-w-0 flex-1">
              <div className="font-medium">{t("remote.sandboxUnavailableTitle")}</div>
              <p className="text-muted-foreground">{detail.sandboxUnavailable.remedy}</p>
              {detail.sandboxUnavailable.fixCommand ? (
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <code className="max-w-full overflow-x-auto rounded border bg-background px-2 py-1 text-xs">
                    {detail.sandboxUnavailable.fixCommand}
                  </code>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => void copyFixCommand(detail.sandboxUnavailable?.fixCommand ?? "")}
                  >
                    <Clipboard className="size-4" />
                    {t("remote.copyFixCommand")}
                  </Button>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}
      {waitingLocks.map((lock) => (
        <div
          key={lock.path}
          className="flex items-center gap-2 rounded-md border bg-muted/40 px-3 py-2 text-sm text-muted-foreground"
        >
          <LoaderCircle className="size-4 shrink-0" />
          <span>{t("remote.waitingForLock", { path: lock.path, holder: lock.holderAgent })}</span>
        </div>
      ))}
      {pausedItems.length ? (
        <div className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <PauseCircle className="size-4 shrink-0 text-primary" />
              <div>
                <div className="font-medium">{t("remote.pausedWorkTitle")}</div>
                <div className="text-muted-foreground">
                  {t("remote.pausedWorkDescription", { count: pausedItems.length })}
                </div>
              </div>
            </div>
            <div className="flex gap-2">
              <Button
                type="button"
                size="sm"
                disabled={actionsDisabled}
                onClick={() => void runPausedAction(onResume)}
              >
                {t("remote.pausedWorkResume")}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={actionsDisabled}
                onClick={() => void runPausedAction(onCancel)}
              >
                {t("remote.pausedWorkCancel")}
              </Button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function projectRootFromRouteParam(projectId: string) {
  const decoded = decodeURIComponent(projectId);
  return decoded.startsWith("/") || decoded.includes("/") ? decoded : null;
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
  sessions: WebSessionSummary[];
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
            {session.description ? (
              <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">{session.description}</p>
            ) : null}
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
  paging,
  onLoadOlder,
  interruptFocus,
  readOnly,
  onResolve,
}: {
  history: WebHistoryEntry[];
  paging: SessionPagingState;
  onLoadOlder: () => Promise<void>;
  interruptFocus?: string;
  readOnly: boolean;
  onResolve: (interruptId: string, selection: InterruptSelection) => Promise<void>;
}) {
  const { t } = useTranslation("instances");
  return (
    <div className="space-y-3">
      {paging.hasMore ? (
        <div className="flex flex-col items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={paging.isLoading}
            onClick={() => void onLoadOlder()}
          >
            {paging.isLoading
              ? t("remote.loadingOlder")
              : paging.error
                ? t("remote.loadOlderRetry")
                : t("remote.loadOlder")}
          </Button>
          {paging.error ? <p className="text-xs text-destructive">{paging.error}</p> : null}
        </div>
      ) : null}
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
  entry: WebHistoryEntry;
  focused: boolean;
  readOnly: boolean;
  onResolve: (interruptId: string, selection: InterruptSelection) => Promise<void>;
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
  if (entry.kind === "inference_failure")
    return (
      <div className="max-w-3xl rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
        <div className="flex items-start gap-2">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-destructive" />
          <div className="min-w-0 flex-1">
            <div className="font-medium">{t("remote.inferenceFailureTitle")}</div>
            <p className="mt-1 text-muted-foreground">
              {t(entry.failure.recovery.messageKey, {
                status: entry.failure.recovery.status,
                feature: entry.failure.recovery.feature,
                provider: entry.failure.recovery.provider,
              })}
            </p>
            <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
              <span>
                {entry.failure.provider}/{entry.failure.model}
              </span>
              <span>{entry.failure.errorClass}</span>
            </div>
            <p className="mt-2 whitespace-pre-wrap">{entry.failure.detail}</p>
          </div>
        </div>
      </div>
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
  if (entry.kind === "interrupt_decision")
    return (
      <div className="rounded-md border bg-muted/30 p-3 text-sm">
        <div className="font-medium">
          {entry.decision.cancelled
            ? t("remote.interruptDecisionCancelled")
            : t("remote.interruptDecisionAnswered")}
        </div>
        <div className="mt-1 text-xs text-muted-foreground">
          {entry.decision.permission
            ? t("remote.interruptDecisionPermission")
            : t("remote.interruptDecisionQuestion")}
        </div>
        {entry.decision.lines.length ? (
          <dl className="mt-3 space-y-2">
            {entry.decision.lines.map((line, index) => (
              <div key={`${line.prompt}:${index}`}>
                <dt className="text-xs text-muted-foreground">{line.prompt}</dt>
                <dd className="whitespace-pre-wrap">{line.answer}</dd>
              </div>
            ))}
          </dl>
        ) : null}
      </div>
    );
  if (entry.kind === "interrupt") {
    return (
      <InterruptTranscriptCard
        entry={entry}
        focused={focused}
        readOnly={readOnly}
        onResolve={onResolve}
      />
    );
  }
  return <div className="rounded-md border p-3 text-sm text-muted-foreground">{entry.kind}</div>;
}

type InterruptHistoryEntry = Extract<WebHistoryEntry, { kind: "interrupt" }>;

function InterruptTranscriptCard({
  entry,
  focused,
  readOnly,
  onResolve,
}: {
  entry: InterruptHistoryEntry;
  focused: boolean;
  readOnly: boolean;
  onResolve: (interruptId: string, selection: InterruptSelection) => Promise<void>;
}) {
  const { t } = useTranslation("instances");
  const [text, setText] = useState("");
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const view = interruptView(entry.interrupt.question, { readOnly });
  const interruptId = entry.interrupt.interruptId;

  const resolve = (selection: InterruptSelection) => {
    void onResolve(interruptId, selection);
  };

  const toggleSelected = (optionId: string) => {
    setSelectedIds((current) =>
      current.includes(optionId)
        ? current.filter((selectedId) => selectedId !== optionId)
        : [...current, optionId],
    );
  };

  return (
    <Card className={focused ? "border-primary" : ""}>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle className="text-base">{view.prompt}</CardTitle>
          <span className="rounded-full border px-2 py-0.5 text-xs text-muted-foreground">
            {view.frame === "approval"
              ? t("remote.interruptFrameApproval")
              : t("remote.interruptFrameQuestion")}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {entry.interrupt.body && !(view.kind === "single" && view.commandDetail) ? (
          <p className="text-sm text-muted-foreground">{entry.interrupt.body}</p>
        ) : null}
        {view.kind === "single" ? <InterruptCommandDetail view={view} /> : null}
        {entry.interrupt.resolved ? (
          <p className="text-sm text-muted-foreground">{t("remote.interruptResolved")}</p>
        ) : readOnly ? (
          <p className="text-sm text-muted-foreground">{t("remote.readOnlyInterruptNotice")}</p>
        ) : (
          <>
            {view.kind === "single" ? (
              <SingleInterruptActions view={view} text={text} setText={setText} resolve={resolve} />
            ) : null}
            {view.kind === "multi" ? (
              <MultiInterruptActions
                view={view}
                text={text}
                setText={setText}
                selectedIds={selectedIds}
                toggleSelected={toggleSelected}
                resolve={resolve}
              />
            ) : null}
            {view.kind === "freetext" ? (
              <div className="space-y-2">
                <Input
                  type={view.inputType}
                  value={text}
                  onChange={(event) => setText(event.target.value)}
                  placeholder={t("remote.interruptAnswerPlaceholder")}
                />
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" onClick={() => resolve({ kind: "freetext", text })}>
                    {t("remote.interruptAnswer")}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => resolve({ kind: "cancel" })}>
                    {t("remote.interruptDecline")}
                  </Button>
                </div>
              </div>
            ) : null}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function SingleInterruptActions({
  view,
  text,
  setText,
  resolve,
}: {
  view: Extract<InterruptView, { kind: "single" }>;
  text: string;
  setText: (text: string) => void;
  resolve: (selection: InterruptSelection) => void;
}) {
  const { t } = useTranslation("instances");
  const hasAnyOption =
    view.primaryOptions.length > 0 ||
    view.secondaryOptions.length > 0 ||
    (view.commandDetail?.scopeChoices.length ?? 0) > 0;

  return (
    <div className="space-y-3">
      <OptionButtonGroup
        options={view.primaryOptions}
        onSelect={(optionId) => resolve({ kind: "single", selectedId: optionId })}
      />

      {view.commandDetail?.scopeChoices.length ? (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground">
            {t("remote.interruptGrantScope")}
          </p>
          <div className="flex flex-wrap gap-2">
            {view.commandDetail.scopeChoices.map((scope) => (
              <Button
                key={scope.optionId}
                size="sm"
                variant="outline"
                onClick={() => resolve({ kind: "single", selectedId: scope.optionId })}
              >
                {t(scope.labelKey, { scope: scope.scope })}
              </Button>
            ))}
          </div>
        </div>
      ) : null}

      {view.sandboxEscalation ? <SandboxEscalationDetail view={view} /> : null}

      {view.secondaryOptions.length ? (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground">
            {t("remote.interruptAdditionalAccess")}
          </p>
          <OptionButtonGroup
            options={view.secondaryOptions}
            variant="outline"
            onSelect={(optionId) => resolve({ kind: "single", selectedId: optionId })}
          />
        </div>
      ) : null}

      {view.freeText ? (
        <div className="space-y-2">
          <Input
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder={t("remote.interruptCustomAnswerPlaceholder")}
          />
          <Button size="sm" onClick={() => resolve({ kind: "freetext", text })}>
            {t("remote.interruptAnswer")}
          </Button>
        </div>
      ) : null}

      {!hasAnyOption && !view.freeText && !view.permission ? (
        <Button size="sm" variant="outline" onClick={() => resolve({ kind: "cancel" })}>
          {t("remote.interruptAcknowledge")}
        </Button>
      ) : null}

      <Button size="sm" variant="outline" onClick={() => resolve({ kind: "cancel" })}>
        {t("remote.interruptDecline")}
      </Button>
    </div>
  );
}

function MultiInterruptActions({
  view,
  text,
  setText,
  selectedIds,
  toggleSelected,
  resolve,
}: {
  view: Extract<InterruptView, { kind: "multi" }>;
  text: string;
  setText: (text: string) => void;
  selectedIds: string[];
  toggleSelected: (optionId: string) => void;
  resolve: (selection: InterruptSelection) => void;
}) {
  const { t } = useTranslation("instances");
  return (
    <div className="space-y-3">
      <MultiOptionButtons
        options={view.primaryOptions}
        selectedIds={selectedIds}
        toggleSelected={toggleSelected}
      />
      {view.secondaryOptions.length ? (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground">
            {t("remote.interruptAdditionalChoices")}
          </p>
          <MultiOptionButtons
            options={view.secondaryOptions}
            selectedIds={selectedIds}
            toggleSelected={toggleSelected}
          />
        </div>
      ) : null}
      {view.freeText ? (
        <Input
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder={t("remote.interruptCustomAnswerPlaceholder")}
        />
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          disabled={selectedIds.length === 0}
          onClick={() => resolve({ kind: "multi", selectedIds })}
        >
          {t("remote.interruptSubmitChoices")}
        </Button>
        {view.freeText ? (
          <Button size="sm" variant="outline" onClick={() => resolve({ kind: "freetext", text })}>
            {t("remote.interruptAnswer")}
          </Button>
        ) : null}
        <Button size="sm" variant="outline" onClick={() => resolve({ kind: "cancel" })}>
          {t("remote.interruptDecline")}
        </Button>
      </div>
    </div>
  );
}

function OptionButtonGroup({
  options,
  variant,
  onSelect,
}: {
  options: { id: string; label: string; description?: string }[];
  variant?: "default" | "outline";
  onSelect: (optionId: string) => void;
}) {
  if (!options.length) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {options.map((option) => (
        <div key={option.id} className="space-y-1">
          <Button size="sm" variant={variant} onClick={() => onSelect(option.id)}>
            {option.label}
          </Button>
          {option.description ? (
            <p className="max-w-sm text-xs text-muted-foreground">{option.description}</p>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function MultiOptionButtons({
  options,
  selectedIds,
  toggleSelected,
}: {
  options: { id: string; label: string; description?: string }[];
  selectedIds: string[];
  toggleSelected: (optionId: string) => void;
}) {
  if (!options.length) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {options.map((option) => {
        const selected = selectedIds.includes(option.id);
        return (
          <div key={option.id} className="space-y-1">
            <Button
              size="sm"
              variant={selected ? "default" : "outline"}
              onClick={() => toggleSelected(option.id)}
            >
              {option.label}
            </Button>
            {option.description ? (
              <p className="max-w-sm text-xs text-muted-foreground">{option.description}</p>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

function InterruptCommandDetail({ view }: { view: Extract<InterruptView, { kind: "single" }> }) {
  const { t } = useTranslation("instances");
  const command = view.commandDetail;
  if (!command) return null;
  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={`rounded-full border px-2 py-0.5 text-xs ${riskBadgeClass(command.risk.variant)}`}
        >
          {command.risk.label}
        </span>
        {view.approvalClassLabelKey ? (
          <span className="rounded-full border px-2 py-0.5 text-xs text-muted-foreground">
            {t(view.approvalClassLabelKey)}
          </span>
        ) : null}
        <span className="text-xs text-muted-foreground">{command.stepLabel}</span>
      </div>
      <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words rounded bg-background p-2 text-xs">
        {command.fullCommand}
      </pre>
      {command.cwd ? (
        <p className="text-xs text-muted-foreground">
          {t("remote.interruptCwd", { cwd: command.cwd })}
        </p>
      ) : null}
      {command.reasons.length ? (
        <p className="text-xs text-muted-foreground">
          {t("remote.interruptReasons", { reasons: command.reasons.join(", ") })}
        </p>
      ) : null}
      {command.affectedTargets.length ? (
        <p className="text-xs text-muted-foreground">
          {t("remote.interruptAffected", { targets: command.affectedTargets.join(", ") })}
        </p>
      ) : null}
      {command.policyCap ? (
        <p className="text-xs text-muted-foreground">
          {t("remote.interruptPolicyCap", { cap: command.policyCap })}
        </p>
      ) : null}
      {command.nativeToolHints.length ? (
        <p className="text-xs text-muted-foreground">
          {t("remote.interruptHints", { hints: command.nativeToolHints.join(", ") })}
        </p>
      ) : null}
      {command.writeContent ? (
        <div className="rounded border bg-background p-2">
          <p className="mb-1 text-xs text-muted-foreground">
            {command.writeContent.dynamic
              ? t("remote.interruptWriteContentDynamic")
              : t("remote.interruptWriteContent")}
          </p>
          <pre className="max-h-28 overflow-auto whitespace-pre-wrap break-words text-xs">
            {command.writeContent.preview}
            {command.writeContent.truncated ? "..." : ""}
          </pre>
        </div>
      ) : null}
    </div>
  );
}

function SandboxEscalationDetail({ view }: { view: Extract<InterruptView, { kind: "single" }> }) {
  const { t } = useTranslation("instances");
  const escalation = view.sandboxEscalation;
  if (!escalation) return null;
  return (
    <div className="space-y-1 rounded-md border border-warning/50 bg-warning/5 p-3 text-xs">
      <p className="font-medium text-warning">{t("remote.interruptSandboxEscalation")}</p>
      <p>{t("remote.interruptSandboxExit", { code: escalation.confinedExit })}</p>
      <p className="whitespace-pre-wrap break-words">
        {t("remote.interruptSandboxStderr", {
          stderr: `${escalation.confinedStderrPreview}${escalation.confinedStderrTruncated ? "..." : ""}`,
        })}
      </p>
      {escalation.suggestedPaths.length ? (
        <p>
          {t("remote.interruptSandboxPaths", {
            paths: escalation.suggestedPaths.join(", "),
          })}
        </p>
      ) : null}
      {escalation.suggestedAccess ? (
        <p>{t("remote.interruptSandboxAccess", { access: escalation.suggestedAccess })}</p>
      ) : null}
      {escalation.denial ? (
        <p>
          {t("remote.interruptSandboxDenial", {
            confidence: escalation.denial.confidence,
            count: escalation.denial.evidenceCount,
          })}
        </p>
      ) : null}
    </div>
  );
}

function riskBadgeClass(variant: RiskVariant) {
  if (variant === "low") return "border-emerald-500/50 text-emerald-700";
  if (variant === "medium") return "border-amber-500/50 text-amber-700";
  if (variant === "high" || variant === "critical") return "border-destructive/60 text-destructive";
  return "text-muted-foreground";
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
  session: WebSessionSummary;
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
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");

  async function submit() {
    const selectedProvider = provider.trim();
    const selectedModel = model.trim();
    try {
      const result = await createSession(instanceId, {
        projectRoot,
        title: title || undefined,
        agent,
        initialModel:
          selectedProvider && selectedModel
            ? { provider: selectedProvider, model: selectedModel }
            : undefined,
      });
      setOpen(false);
      setTitle("");
      setProvider("");
      setModel("");
      onCreated(result.summary.sessionId);
    } catch (error) {
      if (error instanceof WebSessionCreatedWithSetupError) {
        setOpen(false);
        setTitle("");
        setProvider("");
        setModel("");
        onCreated(error.session.summary.sessionId);
        toast.error(t("remote.createSetupFailed"));
      } else {
        toast.error(t("remote.createFailed"));
      }
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
            <Label>{t("remote.provider")}</Label>
            <Input value={provider} onChange={(event) => setProvider(event.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>{t("remote.model")}</Label>
            <Input value={model} onChange={(event) => setModel(event.target.value)} />
          </div>
          <Button
            type="button"
            className="w-full"
            disabled={Boolean(provider.trim()) !== Boolean(model.trim())}
            onClick={() => void submit()}
          >
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
