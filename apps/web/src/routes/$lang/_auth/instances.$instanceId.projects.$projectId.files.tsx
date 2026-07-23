import type { FsEntry, FsReadResult, GitStatusResult } from "@flycockpit/cockpit-protocol";
import { Button } from "@flycockpit/ui/components/button";
import { Card, CardContent, CardHeader, CardTitle } from "@flycockpit/ui/components/card";
import { Checkbox } from "@flycockpit/ui/components/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@flycockpit/ui/components/dialog";
import { Input } from "@flycockpit/ui/components/input";
import { Label } from "@flycockpit/ui/components/label";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@flycockpit/ui/components/sheet";
import { toast } from "@flycockpit/ui/components/sileo";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { Textarea } from "@flycockpit/ui/components/textarea";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  ArrowLeft,
  File,
  FilePlus,
  Folder,
  FolderPlus,
  GitBranch,
  Pencil,
  Save,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import type { FormEvent } from "react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useShallow } from "zustand/react/shallow";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { InlineRetry } from "@/components/inline-retry";
import { useRemoteInstanceConnection } from "@/hooks/use-remote-instance-connection";
import {
  canEditFile,
  childPath,
  decodeFileRoutePath,
  encodeFileRoutePath,
  parentPath,
  type SaveState,
  saveReducer,
  visibleEntries,
} from "@/lib/file-browser-state";
import { useRemoteSessionsStore } from "@/stores/remote-sessions";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute(
  "/$lang/_auth/instances/$instanceId/projects/$projectId/files",
)({
  validateSearch: (search: Record<string, unknown>) => ({
    path: typeof search.path === "string" ? search.path : undefined,
    file: typeof search.file === "string" ? search.file : undefined,
    showHidden: search.showHidden === true || search.showHidden === "true",
  }),
  component: ProjectFilesPage,
});

function ProjectFilesPage() {
  const { lang, instanceId, projectId } = Route.useParams();
  const search = Route.useSearch();
  const { t } = useTranslation("instances");
  const navigate = useNavigate({ from: Route.fullPath });
  const queryClient = useQueryClient();
  const directoryPath = decodeFileRoutePath(search.path);
  const selectedFile = decodeFileRoutePath(search.file);
  const showHidden = search.showHidden;
  const [deleteEntry, setDeleteEntry] = useState<FsEntry | null>(null);
  const {
    data: tokenData,
    error: tokenError,
    isError: tokenIsError,
    isPending: tokenIsPending,
    refetch: refetchToken,
  } = useQuery(orpc.instances.mintClientToken.queryOptions({ input: { instanceId } }));
  useRemoteInstanceConnection(instanceId, tokenData);
  const {
    remote,
    listFiles,
    readFile,
    writeFile,
    createDirectory,
    renamePath,
    deletePath,
    gitStatus,
    gitDiffFile,
  } = useRemoteSessionsStore(
    useShallow((state) => ({
      remote: state.instances[instanceId],
      listFiles: state.listFiles,
      readFile: state.readFile,
      writeFile: state.writeFile,
      createDirectory: state.createDirectory,
      renamePath: state.renamePath,
      deletePath: state.deletePath,
      gitStatus: state.gitStatus,
      gitDiffFile: state.gitDiffFile,
    })),
  );
  const project = remote?.projects.find((item) => item.projectId === projectId);
  const projectRoot = project?.projectRoot ?? projectRootFromRouteParam(projectId);
  const connected = remote?.status === "connected";

  const {
    data: directoryData,
    isError: directoryIsError,
    isPending: directoryIsPending,
    refetch: refetchDirectory,
  } = useQuery({
    queryKey: ["remote-files", instanceId, projectRoot, directoryPath, showHidden],
    enabled: connected && Boolean(projectRoot),
    queryFn: () =>
      listFiles(instanceId, {
        projectRoot: requireProjectRoot(projectRoot),
        path: directoryPath,
        showHidden,
      }),
  });
  const entries = visibleEntries(directoryData?.entries ?? [], showHidden);
  const selectedEntry = entries.find((entry) => entry.path === selectedFile) ?? null;
  const {
    data: fileData,
    error: fileError,
    isError: fileIsError,
    isPending: fileIsPending,
    refetch: refetchFile,
  } = useQuery({
    queryKey: ["remote-file", instanceId, projectRoot, selectedFile],
    enabled: connected && Boolean(projectRoot) && Boolean(selectedFile),
    queryFn: () =>
      readFile(instanceId, { projectRoot: requireProjectRoot(projectRoot), path: selectedFile }),
  });
  const { data: statusData } = useQuery({
    queryKey: ["remote-git-status", instanceId, projectRoot],
    enabled: connected && Boolean(projectRoot),
    queryFn: () => gitStatus(instanceId, { projectRoot: requireProjectRoot(projectRoot) }),
  });
  const {
    data: diffData,
    isError: diffIsError,
    isPending: diffIsPending,
    refetch: refetchDiff,
  } = useQuery({
    queryKey: ["remote-git-diff", instanceId, projectRoot, selectedFile],
    enabled: connected && Boolean(projectRoot) && Boolean(selectedFile),
    queryFn: () =>
      gitDiffFile(instanceId, { projectRoot: requireProjectRoot(projectRoot), path: selectedFile }),
  });

  const invalidateProjectFiles = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["remote-files", instanceId, projectRoot] }),
      queryClient.invalidateQueries({ queryKey: ["remote-file", instanceId, projectRoot] }),
      queryClient.invalidateQueries({ queryKey: ["remote-git-status", instanceId, projectRoot] }),
      queryClient.invalidateQueries({ queryKey: ["remote-git-diff", instanceId, projectRoot] }),
    ]);
  };

  const createMutation = useMutation({
    mutationFn: async (input: { kind: "file" | "directory"; name: string }) => {
      const target = childPath(directoryPath, input.name);
      if (input.kind === "directory") {
        await createDirectory(instanceId, {
          projectRoot: requireProjectRoot(projectRoot),
          path: target,
        });
      } else {
        await writeFile(instanceId, {
          projectRoot: requireProjectRoot(projectRoot),
          path: target,
          content: "",
        });
      }
      return { ...input, path: target };
    },
    onSuccess: async (result) => {
      toast.success(t("files.created"));
      await invalidateProjectFiles();
      if (result.kind === "file") {
        await navigate({
          search: {
            path: encodeFileRoutePath(directoryPath),
            file: encodeFileRoutePath(result.path),
            showHidden,
            session: undefined,
            interrupt: undefined,
          },
        });
      } else {
        await navigate({
          search: {
            path: encodeFileRoutePath(result.path),
            file: undefined,
            showHidden,
            session: undefined,
            interrupt: undefined,
          },
        });
      }
    },
    onError: (error) => toast.error(friendly(error, t("files.createFailed"))),
  });
  const renameMutation = useMutation({
    mutationFn: async (input: { entry: FsEntry; name: string }) => {
      const toPath = childPath(parentPath(input.entry.path), input.name);
      await renamePath(instanceId, {
        projectRoot: requireProjectRoot(projectRoot),
        fromPath: input.entry.path,
        toPath,
      });
      return { entry: input.entry, toPath };
    },
    onSuccess: async (result) => {
      toast.success(t("files.renamed"));
      await invalidateProjectFiles();
      const nextDirectory =
        result.entry.kind === "directory" ? result.toPath : parentPath(result.toPath);
      await navigate({
        search: {
          path: encodeFileRoutePath(nextDirectory),
          file: result.entry.kind === "directory" ? undefined : encodeFileRoutePath(result.toPath),
          showHidden,
          session: undefined,
          interrupt: undefined,
        },
      });
    },
    onError: (error) => toast.error(friendly(error, t("files.renameFailed"))),
  });
  const deleteMutation = useMutation({
    mutationFn: async (entry: FsEntry) => {
      await deletePath(instanceId, {
        projectRoot: requireProjectRoot(projectRoot),
        path: entry.path,
      });
      return entry;
    },
    onSuccess: async (entry) => {
      toast.success(t("files.deleted"));
      setDeleteEntry(null);
      await invalidateProjectFiles();
      await navigate({
        search: {
          path: encodeFileRoutePath(parentPath(entry.path)),
          file: undefined,
          showHidden,
          session: undefined,
          interrupt: undefined,
        },
      });
    },
    onError: (error) => toast.error(friendly(error, t("files.deleteFailed"))),
  });

  if (tokenIsPending) return <FilesSkeleton />;
  if (tokenIsError) {
    return (
      <InlineRetry
        className="container mx-auto max-w-6xl px-4 py-12"
        message={friendly(tokenError, t("files.loadFailed"))}
        onRetry={() => refetchToken()}
      />
    );
  }

  return (
    <div className="container mx-auto flex min-h-0 max-w-7xl flex-col px-4 py-6">
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <Link
            to="/$lang/instances/$instanceId/projects/$projectId"
            params={{ lang, instanceId, projectId }}
            search={{ session: undefined, interrupt: undefined }}
            className="mb-2 inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="size-4" />
            {t("files.backToSessions")}
          </Link>
          <h1 className="truncate text-2xl font-semibold tracking-tight">
            {project?.displayName ?? t("files.title")}
          </h1>
          <p className="truncate text-sm text-muted-foreground">{projectRoot ?? projectId}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <CreateEntryDialog
            connected={connected && Boolean(projectRoot)}
            isPending={createMutation.isPending}
            onSubmit={(input) => createMutation.mutate(input)}
          />
          <label className="flex min-h-[44px] items-center gap-2 rounded-md border px-3 text-sm">
            <Checkbox
              checked={showHidden}
              onCheckedChange={(checked) =>
                navigate({
                  search: {
                    path: search.path,
                    file: search.file,
                    showHidden: checked === true,
                    session: undefined,
                    interrupt: undefined,
                  },
                })
              }
            />
            {t("files.showHidden")}
          </label>
        </div>
      </div>

      {!connected ? (
        <div className="mb-4 rounded-md border bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
          {t("remote.offlineBanner")}
        </div>
      ) : null}

      <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[19rem_1fr_18rem]">
        <Card className="min-h-0">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">{t("files.tree")}</CardTitle>
            <Breadcrumbs
              lang={lang}
              instanceId={instanceId}
              projectId={projectId}
              path={directoryPath}
              showHidden={showHidden}
            />
          </CardHeader>
          <CardContent className="space-y-2">
            {directoryPath ? (
              <FileLink
                lang={lang}
                instanceId={instanceId}
                projectId={projectId}
                directoryPath={parentPath(directoryPath)}
                showHidden={showHidden}
                label={t("files.up")}
                kind="directory"
              />
            ) : null}
            {directoryIsPending ? <DirectorySkeleton /> : null}
            {directoryIsError ? (
              <InlineRetry message={t("files.loadFailed")} onRetry={() => refetchDirectory()} />
            ) : null}
            {entries.map((entry) => (
              <FileEntryLink
                key={entry.path}
                entry={entry}
                lang={lang}
                instanceId={instanceId}
                projectId={projectId}
                directoryPath={directoryPath}
                showHidden={showHidden}
              />
            ))}
            {directoryData?.truncated ? (
              <p className="text-xs text-muted-foreground">{t("files.truncatedDirectory")}</p>
            ) : null}
          </CardContent>
        </Card>

        <Card className="min-h-[28rem] min-w-0">
          <CardHeader className="flex-row items-start justify-between gap-3 pb-3">
            <div className="min-w-0">
              <CardTitle className="truncate text-base">
                {selectedFile || t("files.viewer")}
              </CardTitle>
              {selectedEntry ? <FileMeta entry={selectedEntry} /> : null}
            </div>
            {selectedEntry && !selectedEntry.blocked ? (
              <div className="flex shrink-0 gap-2">
                <RenameEntrySheet
                  entry={selectedEntry}
                  isPending={renameMutation.isPending}
                  onSubmit={(name) => renameMutation.mutate({ entry: selectedEntry, name })}
                />
                <Button
                  type="button"
                  variant="outline"
                  size="icon-sm"
                  className="min-h-[44px] min-w-[44px]"
                  onClick={() => setDeleteEntry(selectedEntry)}
                  aria-label={t("files.delete")}
                  disabled={!connected}
                >
                  <Trash2 className="size-4" />
                </Button>
              </div>
            ) : null}
          </CardHeader>
          <CardContent className="min-w-0">
            {!selectedFile ? (
              <div className="py-16 text-center text-sm text-muted-foreground">
                {t("files.selectFile")}
              </div>
            ) : fileIsPending ? (
              <Skeleton className="h-80 rounded-md" />
            ) : fileIsError ? (
              <InlineRetry
                message={friendly(fileError, t("files.readFailed"))}
                onRetry={() => refetchFile()}
              />
            ) : (
              <FileViewer
                key={selectedFile + ":" + fileData.hash}
                value={fileData}
                path={selectedFile}
                connected={connected}
                blocked={selectedEntry?.blocked ?? false}
                writeFile={(content, baseHash) =>
                  writeFile(instanceId, {
                    projectRoot: requireProjectRoot(projectRoot),
                    path: selectedFile,
                    content,
                    baseHash,
                  })
                }
                onSaved={invalidateProjectFiles}
              />
            )}
          </CardContent>
        </Card>

        <Card className="min-h-0">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <GitBranch className="size-4" />
              {t("files.changes")}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <GitSummary status={statusData} />
            {selectedFile ? (
              <div className="space-y-2">
                <h3 className="text-sm font-medium">{t("files.diff")}</h3>
                {diffIsPending ? <Skeleton className="h-48 rounded-md" /> : null}
                {diffIsError ? (
                  <InlineRetry message={t("files.loadFailed")} onRetry={() => refetchDiff()} />
                ) : null}
                {diffData ? (
                  <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs leading-relaxed">
                    {diffData.diff || t("files.noDiff")}
                    {diffData.truncated ? "\n" + t("files.truncatedDiff") : ""}
                  </pre>
                ) : null}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>

      <ConfirmDeleteDialog
        open={Boolean(deleteEntry)}
        onOpenChange={(open) => {
          if (!open) setDeleteEntry(null);
        }}
        title={t("files.deleteTitle")}
        description={t("files.deleteDescription")}
        confirmToken={deleteEntry?.path ?? ""}
        typePrompt={t("files.deleteTypePrompt")}
        copyAriaLabel={t("files.deleteCopyLabel")}
        isPending={deleteMutation.isPending}
        pendingLabel={t("files.deleting")}
        onConfirm={() => {
          if (deleteEntry) deleteMutation.mutate(deleteEntry);
        }}
      />
    </div>
  );
}

function projectRootFromRouteParam(projectId: string) {
  const decoded = decodeURIComponent(projectId);
  return decoded.startsWith("/") || decoded.includes("/") ? decoded : null;
}

function requireProjectRoot(projectRoot: string | null) {
  if (!projectRoot) throw new Error("Project root is not loaded.");
  return projectRoot;
}

function CreateEntryDialog({
  connected,
  isPending,
  onSubmit,
}: {
  connected: boolean;
  isPending: boolean;
  onSubmit: (input: { kind: "file" | "directory"; name: string }) => void;
}) {
  const { t } = useTranslation("instances");
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<"file" | "directory">("file");
  const [name, setName] = useState("");
  const trimmed = name.trim();
  function submit(event: FormEvent) {
    event.preventDefault();
    if (!trimmed) return;
    onSubmit({ kind, name: trimmed });
    setName("");
    setOpen(false);
  }
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button type="button" disabled={!connected} />}>
        <FilePlus className="size-4" />
        {t("files.create")}
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("files.createTitle")}</DialogTitle>
          <DialogDescription>{t("files.createDescription")}</DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={submit}>
          <div className="grid grid-cols-2 gap-2">
            <Button
              type="button"
              variant={kind === "file" ? "default" : "outline"}
              onClick={() => setKind("file")}
            >
              <FilePlus className="size-4" />
              {t("files.createFile")}
            </Button>
            <Button
              type="button"
              variant={kind === "directory" ? "default" : "outline"}
              onClick={() => setKind("directory")}
            >
              <FolderPlus className="size-4" />
              {t("files.createDirectory")}
            </Button>
          </div>
          <div className="space-y-2">
            <Label htmlFor="file-create-name">{t("files.nameLabel")}</Label>
            <Input
              id="file-create-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder={t("files.namePlaceholder")}
              autoComplete="off"
            />
          </div>
          <DialogFooter>
            <Button type="submit" disabled={!trimmed || isPending}>
              {isPending ? t("files.creating") : t("files.create")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RenameEntrySheet({
  entry,
  isPending,
  onSubmit,
}: {
  entry: FsEntry;
  isPending: boolean;
  onSubmit: (name: string) => void;
}) {
  const { t } = useTranslation("instances");
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(entry.name);
  const trimmed = name.trim();
  function submit(event: FormEvent) {
    event.preventDefault();
    if (!trimmed || trimmed === entry.name) return;
    onSubmit(trimmed);
    setOpen(false);
  }
  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger
        render={
          <Button
            type="button"
            variant="outline"
            size="icon-sm"
            className="min-h-[44px] min-w-[44px]"
          />
        }
      >
        <Pencil className="size-4" />
        <span className="sr-only">{t("files.rename")}</span>
      </SheetTrigger>
      <SheetContent className="sm:max-w-md">
        <SheetHeader>
          <SheetTitle>{t("files.renameTitle")}</SheetTitle>
          <SheetDescription>{t("files.renameDescription")}</SheetDescription>
        </SheetHeader>
        <form className="flex flex-1 flex-col gap-4 p-4" onSubmit={submit}>
          <div className="space-y-2">
            <Label htmlFor="file-rename-name">{t("files.newNameLabel")}</Label>
            <Input
              id="file-rename-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              autoComplete="off"
            />
          </div>
          <SheetFooter className="px-0 pb-0">
            <Button type="submit" disabled={!trimmed || trimmed === entry.name || isPending}>
              {isPending ? t("files.renaming") : t("files.rename")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}

function FileViewer({
  value,
  path,
  connected,
  blocked,
  writeFile,
  onSaved,
}: {
  value: FsReadResult;
  path: string;
  connected: boolean;
  blocked: boolean;
  writeFile: (content: string, baseHash?: string) => Promise<{ hash: string }>;
  onSaved: () => Promise<void>;
}) {
  const { t } = useTranslation("instances");
  const [content, setContent] = useState(value.content ?? "");
  const [state, setState] = useState<SaveState>({ status: "clean", baseHash: value.hash });
  const save = useMutation({
    mutationFn: async () => writeFile(content, state.baseHash ?? undefined),
    onMutate: () => setState((current) => saveReducer(current, { type: "save" })),
    onSuccess: async (result) => {
      setState((current) => saveReducer(current, { type: "saved", hash: result.hash }));
      toast.success(t("files.saved"));
      await onSaved();
    },
    onError: (error) => {
      setState((current) =>
        saveReducer(current, { type: "conflict", message: friendly(error, t("files.saveFailed")) }),
      );
    },
  });

  if (value.kind === "image" && value.content) {
    return (
      <img
        alt={path}
        className="max-h-[70vh] rounded-md border object-contain"
        src={imageDataUrl(path, value.content)}
      />
    );
  }
  if (value.kind !== "text") {
    return (
      <div className="rounded-md border bg-muted/30 p-4 text-sm text-muted-foreground">
        {t("files.binaryState")}
      </div>
    );
  }

  const editable = canEditFile({ connected, blocked, kind: value.kind });
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-muted-foreground">
        <span>{state.status === "dirty" ? t("files.dirty") : t("files.clean")}</span>
        <Button
          type="button"
          disabled={!editable || state.status !== "dirty" || save.isPending}
          onClick={() => save.mutate()}
        >
          <Save className="size-4" />
          {save.isPending ? t("files.saving") : t("files.save")}
        </Button>
      </div>
      {state.status === "conflict" ? (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
          {state.message}
        </div>
      ) : null}
      {blocked ? (
        <div className="rounded-md border bg-muted/30 p-3 text-sm text-muted-foreground">
          {t("files.blockedByOwnerPolicy")}
        </div>
      ) : null}
      {value.truncated ? (
        <p className="text-sm text-muted-foreground">{t("files.truncatedFile")}</p>
      ) : null}
      <Textarea
        className="min-h-[28rem] resize-y font-mono text-sm"
        value={content}
        disabled={!editable}
        spellCheck={false}
        onChange={(event) => {
          setContent(event.target.value);
          setState((current) => saveReducer(current, { type: "edit" }));
        }}
      />
    </div>
  );
}

function FileEntryLink({
  entry,
  lang,
  instanceId,
  projectId,
  directoryPath,
  showHidden,
}: {
  entry: FsEntry;
  lang: string;
  instanceId: string;
  projectId: string;
  directoryPath: string;
  showHidden: boolean;
}) {
  const { t } = useTranslation("instances");
  if (entry.blocked) {
    return (
      <div className="rounded-md border bg-muted/30 px-3 py-2 text-sm text-muted-foreground">
        <div className="flex items-center gap-2">
          <ShieldAlert className="size-4" />
          <span className="truncate">{entry.name}</span>
        </div>
        <p className="mt-1 pl-6 text-xs">{t("files.blockedByOwnerPolicy")}</p>
      </div>
    );
  }
  return (
    <FileLink
      lang={lang}
      instanceId={instanceId}
      projectId={projectId}
      directoryPath={entry.kind === "directory" ? entry.path : directoryPath}
      filePath={entry.kind === "directory" ? undefined : entry.path}
      showHidden={showHidden}
      label={entry.name}
      kind={entry.kind}
      gitignored={entry.gitignored}
    />
  );
}

function FileLink({
  lang,
  instanceId,
  projectId,
  directoryPath,
  filePath,
  showHidden,
  label,
  kind,
  gitignored,
}: {
  lang: string;
  instanceId: string;
  projectId: string;
  directoryPath: string;
  filePath?: string;
  showHidden: boolean;
  label: string;
  kind: string;
  gitignored?: boolean;
}) {
  return (
    <Link
      to="/$lang/instances/$instanceId/projects/$projectId/files"
      params={{ lang, instanceId, projectId }}
      search={{
        path: encodeFileRoutePath(directoryPath),
        file: filePath ? encodeFileRoutePath(filePath) : undefined,
        showHidden,
        session: undefined,
        interrupt: undefined,
      }}
      className={
        "flex min-h-[44px] items-center gap-2 rounded-md border px-3 py-2 text-sm hover:bg-muted " +
        (gitignored ? "text-muted-foreground opacity-70" : "")
      }
    >
      {kind === "directory" ? <Folder className="size-4" /> : <File className="size-4" />}
      <span className="truncate">{label}</span>
    </Link>
  );
}

function Breadcrumbs({
  lang,
  instanceId,
  projectId,
  path,
  showHidden,
}: {
  lang: string;
  instanceId: string;
  projectId: string;
  path: string;
  showHidden: boolean;
}) {
  const parts = path.split("/").filter(Boolean);
  let acc = "";
  return (
    <div className="flex flex-wrap gap-1 text-xs text-muted-foreground">
      <Link
        to="/$lang/instances/$instanceId/projects/$projectId/files"
        params={{ lang, instanceId, projectId }}
        search={{
          path: undefined,
          file: undefined,
          showHidden,
          session: undefined,
          interrupt: undefined,
        }}
      >
        /
      </Link>
      {parts.map((part) => {
        acc = childPath(acc, part);
        return (
          <Link
            key={acc}
            to="/$lang/instances/$instanceId/projects/$projectId/files"
            params={{ lang, instanceId, projectId }}
            search={{
              path: encodeFileRoutePath(acc),
              file: undefined,
              showHidden,
              session: undefined,
              interrupt: undefined,
            }}
          >
            {part}/
          </Link>
        );
      })}
    </div>
  );
}

function FileMeta({ entry }: { entry: FsEntry }) {
  const { t } = useTranslation("instances");
  return (
    <p className="truncate text-xs text-muted-foreground">
      {t("files.kind." + entry.kind)} · {formatBytes(entry.size)}
      {entry.mtime_ms ? " · " + new Date(entry.mtime_ms).toLocaleString() : ""}
      {entry.gitignored ? " · " + t("files.gitignored") : ""}
    </p>
  );
}

function GitSummary({ status }: { status: GitStatusResult | undefined }) {
  const { t } = useTranslation("instances");
  const entries = status?.entries ?? [];
  const dirty = entries.filter(
    (entry) => entry.raw.startsWith("1 ") || entry.raw.startsWith("2 "),
  ).length;
  const untracked = entries.filter((entry) => entry.raw.startsWith("? ")).length;
  return (
    <div className="space-y-3 text-sm">
      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-md border p-3">
          <div className="text-xs text-muted-foreground">{t("files.dirtyFiles")}</div>
          <div className="font-medium tabular-nums">{dirty}</div>
        </div>
        <div className="rounded-md border p-3">
          <div className="text-xs text-muted-foreground">{t("files.untrackedFiles")}</div>
          <div className="font-medium tabular-nums">{untracked}</div>
        </div>
      </div>
      {entries.length ? (
        <div className="max-h-40 space-y-1 overflow-auto rounded-md border bg-muted/20 p-2 font-mono text-xs">
          {entries.map((entry) => (
            <div key={entry.raw} className="truncate">
              {entry.raw}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function formatBytes(size: number) {
  if (size < 1024) return size + " B";
  if (size < 1024 * 1024) return (size / 1024).toFixed(1) + " KB";
  return (size / (1024 * 1024)).toFixed(1) + " MB";
}

function imageDataUrl(path: string, content: string) {
  const lower = path.toLowerCase();
  const mime = lower.endsWith(".svg")
    ? "image/svg+xml"
    : lower.endsWith(".webp")
      ? "image/webp"
      : lower.endsWith(".gif")
        ? "image/gif"
        : lower.endsWith(".jpg") || lower.endsWith(".jpeg")
          ? "image/jpeg"
          : "image/png";
  return "data:" + mime + ";base64," + content;
}

function DirectorySkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 6 }).map((_, index) => (
        <Skeleton key={index} className="h-11 rounded-md" />
      ))}
    </div>
  );
}

function FilesSkeleton() {
  return (
    <div className="container mx-auto max-w-7xl px-4 py-6">
      <Skeleton className="mb-4 h-16 rounded-lg" />
      <div className="grid gap-4 lg:grid-cols-[19rem_1fr_18rem]">
        <Skeleton className="h-96 rounded-lg" />
        <Skeleton className="h-96 rounded-lg" />
        <Skeleton className="h-96 rounded-lg" />
      </div>
    </div>
  );
}
