import { uploadAsset } from "@flycockpit/api/lib/asset-client";
import { Button } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@flycockpit/ui/components/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@flycockpit/ui/components/dropdown-menu";
import { Input } from "@flycockpit/ui/components/input";
import { Label } from "@flycockpit/ui/components/label";
import { toast } from "@flycockpit/ui/components/sileo";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { cn } from "@flycockpit/ui/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  ChevronRight,
  Eye,
  EyeOff,
  Folder,
  FolderRoot,
  MoreVertical,
  Sparkles,
  Trash2,
  Upload,
} from "lucide-react";
import { useId, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { InlineRetry } from "@/components/inline-retry";
import { useHaptics } from "@/hooks/use-haptics";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/admin/assets/")({
  component: AdminAssets,
});

type AssetItem = {
  id: string;
  mimeType: string;
  size: number;
  blurhash: string | null;
  width: number | null;
  height: number | null;
  url: string;
  imageUrl: string | null;
  path: string | null;
  visibility: string;
};

type FolderNode = {
  /** Path string, ending in `/` for folders. `null` = root. */
  path: string | null;
  /** Display name (last segment). */
  name: string;
  count: number;
  children: FolderNode[];
};

function buildFolderTree(
  rows: { path: string | null; count: number }[],
  rootName: string,
): {
  root: FolderNode;
  flat: Map<string | null, FolderNode>;
} {
  const root: FolderNode = {
    path: null,
    name: rootName,
    count: 0,
    children: [],
  };
  const map = new Map<string | null, FolderNode>([[null, root]]);
  // Ensure every intermediate path exists, even if no row uses it directly.
  const ensure = (path: string): FolderNode => {
    const cached = map.get(path);
    if (cached) return cached;
    const segments = path.split("/").filter(Boolean);
    const name = segments[segments.length - 1] ?? "";
    const parentPath = segments.length <= 1 ? null : `/${segments.slice(0, -1).join("/")}/`;
    const parent = parentPath == null ? root : ensure(parentPath);
    const node: FolderNode = { path, name, count: 0, children: [] };
    parent.children.push(node);
    map.set(path, node);
    return node;
  };
  for (const row of rows) {
    if (row.path == null) {
      root.count += row.count;
      continue;
    }
    const node = ensure(row.path);
    node.count += row.count;
  }
  // Total of root = sum across all (visual hint).
  root.count = rows.reduce((sum, r) => sum + r.count, 0);
  return { root, flat: map };
}

function pathBreadcrumb(
  path: string | null,
  rootName: string,
): { path: string | null; name: string }[] {
  if (path == null) return [{ path: null, name: rootName }];
  const segments = path.split("/").filter(Boolean);
  const out: { path: string | null; name: string }[] = [{ path: null, name: rootName }];
  let acc = "";
  for (const seg of segments) {
    acc += `/${seg}/`;
    out.push({ path: acc, name: seg });
  }
  return out;
}

const UPLOAD_CONCURRENCY = 4;

async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<R>,
): Promise<PromiseSettledResult<R>[]> {
  const results: PromiseSettledResult<R>[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const index = next++;
      if (index >= items.length) return;
      try {
        results[index] = { status: "fulfilled", value: await fn(items[index]!) };
      } catch (reason) {
        results[index] = { status: "rejected", reason };
      }
    }
  });
  await Promise.all(workers);
  return results;
}

function getSettledSummary<T>(results: PromiseSettledResult<T>[]) {
  let successCount = 0;
  let failureCount = 0;
  for (const result of results) {
    if (result.status === "fulfilled") successCount += 1;
    else failureCount += 1;
  }
  return { successCount, failureCount };
}

function AdminAssets() {
  const { lang } = Route.useParams();
  const [currentPath, setCurrentPath] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [lastClickedId, setLastClickedId] = useState<string | null>(null);
  const [moveOpen, setMoveOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [singleDelete, setSingleDelete] = useState<AssetItem | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const queryClient = useQueryClient();
  const { trigger } = useHaptics();
  const { t } = useTranslation(["admin", "common"]);

  const paths = useQuery(orpc.assets.listPaths.queryOptions());
  const list = useQuery(
    orpc.assets.listByPath.queryOptions({
      input: { path: currentPath, limit: 100 },
    }),
  );

  const upload = useMutation({
    mutationFn: async (file: File) => {
      const result = await uploadAsset({ file, visibility: "RESTRICTED" });
      // After upload, the asset starts at root path. If the user is in a
      // sub-folder, immediately move it so the new file lands beside the
      // others they're looking at.
      if (currentPath) {
        await orpc.assets.move.call({ ids: [result.id], path: currentPath });
      }
      return result;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: orpc.assets.key() });
    },
  });

  const move = useMutation(
    orpc.assets.move.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.assets.key() });
      },
    }),
  );

  const remove = useMutation({
    ...orpc.assets.delete.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.assets.key() });
      },
    }),
    meta: { skipGlobalErrorToast: true },
  });

  const setVisibility = useMutation(
    orpc.assets.setVisibility.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.assets.key() });
      },
    }),
  );

  const tree = paths.data ? buildFolderTree(paths.data, t("admin:assets.allAssets")) : null;
  const items = (list.data?.items ?? []) as AssetItem[];

  const handleSelect = (
    id: string,
    e: { shiftKey: boolean; metaKey: boolean; ctrlKey: boolean },
  ) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      const ids = items.map((i) => i.id);
      if (e.shiftKey && lastClickedId) {
        const a = ids.indexOf(lastClickedId);
        const b = ids.indexOf(id);
        if (a !== -1 && b !== -1) {
          const [from, to] = a < b ? [a, b] : [b, a];
          for (let i = from; i <= to; i++) {
            const candidate = ids[i];
            if (candidate) next.add(candidate);
          }
          return next;
        }
      }
      if (e.metaKey || e.ctrlKey) {
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      }
      // Plain click → tap-toggle on mobile, sole-select on desktop. Use
      // single-select if nothing was previously selected, else toggle the tap.
      if (next.has(id) && next.size === 1) {
        next.delete(id);
        return next;
      }
      next.clear();
      next.add(id);
      return next;
    });
    setLastClickedId(id);
  };

  const navigateTo = (path: string | null) => {
    setCurrentPath(path);
    setSelectedIds(new Set());
    setLastClickedId(null);
  };

  const handleFiles = async (files: File[]) => {
    if (files.length === 0) return;
    trigger("light");
    const results = await mapWithConcurrency(files, UPLOAD_CONCURRENCY, async (file) => {
      await upload.mutateAsync(file);
      return file;
    });
    for (const result of results) {
      if (result.status === "fulfilled") {
        trigger("success");
        toast.success(t("admin:assets.uploaded", { name: result.value.name }));
      } else {
        trigger("error");
        // Mutation cache surfaces the error toast already.
      }
    }
  };

  return (
    <div className="container mx-auto max-w-7xl px-4 py-8 space-y-4">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("admin:assets.title")}</h1>
          <p className="text-sm text-muted-foreground">{t("admin:assets.description")}</p>
        </div>
        <div className="flex items-center gap-2">
          <input
            ref={fileInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => {
              const list = e.target.files;
              if (!list) return;
              const files = Array.from(list);
              e.currentTarget.value = "";
              void handleFiles(files);
            }}
          />
          <Button
            variant="outline"
            className="min-h-[44px]"
            nativeButton={false}
            render={<Link to="/$lang/admin/assets/cleanup" params={{ lang }} />}
          >
            <Sparkles className="size-4" /> {t("admin:assets.cleanup")}
          </Button>
          <Button
            onClick={() => {
              trigger("light");
              fileInputRef.current?.click();
            }}
            className="min-h-[44px]"
          >
            <Upload className="size-4" /> {t("admin:assets.upload")}
          </Button>
        </div>
      </header>

      <div className="grid grid-cols-12 gap-4">
        <Card className="col-span-12 md:col-span-3">
          <CardHeader>
            <CardTitle>{t("admin:assets.folders")}</CardTitle>
            <CardDescription>{t("admin:assets.foldersDescription")}</CardDescription>
          </CardHeader>
          <CardContent className="p-2">
            {paths.isPending ? (
              <div className="space-y-2 p-2">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={`folder-skel-${i}`} className="h-7 w-full" />
                ))}
              </div>
            ) : paths.isError ? (
              <div className="space-y-2 p-2 text-center">
                <p className="text-xs text-muted-foreground">
                  {t("admin:assets.loadFoldersFailed")}
                </p>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => paths.refetch()}
                  className="min-h-[44px]"
                >
                  {t("common:actions.tryAgain")}
                </Button>
              </div>
            ) : tree ? (
              <FolderTreeView node={tree.root} currentPath={currentPath} onSelect={navigateTo} />
            ) : null}
          </CardContent>
        </Card>

        <Card className="col-span-12 md:col-span-9">
          <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <CardTitle>{currentPath ?? t("admin:assets.root")}</CardTitle>
              <Breadcrumb
                segments={pathBreadcrumb(currentPath, t("admin:assets.allAssets"))}
                onSelect={navigateTo}
              />
            </div>
            {selectedIds.size > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">
                  {t("admin:assets.selectedCount", { count: selectedIds.size })}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  className="min-h-[44px]"
                  onClick={() => {
                    trigger("light");
                    setMoveOpen(true);
                  }}
                >
                  {t("admin:assets.move")}
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  className="min-h-[44px]"
                  onClick={() => {
                    trigger("warning");
                    setDeleteOpen(true);
                  }}
                >
                  <Trash2 className="size-4" /> {t("common:actions.delete")}
                </Button>
              </div>
            )}
          </CardHeader>
          <CardContent>
            <UploadDropZone onFiles={handleFiles} disabled={upload.isPending}>
              {list.isPending ? (
                <GridSkeleton />
              ) : list.isError ? (
                <InlineRetry
                  className="py-12"
                  message={t("admin:assets.loadAssetsFailed")}
                  onRetry={() => list.refetch()}
                />
              ) : items.length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-12 text-center">
                  <p className="text-sm font-medium">{t("admin:assets.noAssetsInFolder")}</p>
                  <p className="text-sm text-muted-foreground">{t("admin:assets.noAssetsHint")}</p>
                </div>
              ) : (
                <ul className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5">
                  {items.map((asset) => (
                    <AssetCard
                      key={asset.id}
                      asset={asset}
                      selected={selectedIds.has(asset.id)}
                      onSelect={(e) => handleSelect(asset.id, e)}
                      onDelete={() => {
                        setSelectedIds(new Set([asset.id]));
                        setSingleDelete(asset);
                      }}
                      onMove={() => {
                        setSelectedIds(new Set([asset.id]));
                        setMoveOpen(true);
                      }}
                      onSetVisibility={async (next) => {
                        trigger("light");
                        await setVisibility.mutateAsync(
                          { id: asset.id, visibility: next },
                          {
                            onSuccess: () => {
                              trigger("success");
                              toast.success(
                                next === "PUBLIC"
                                  ? t("admin:assets.card.publicSetSuccess")
                                  : t("admin:assets.card.restrictedSetSuccess"),
                              );
                            },
                            onError: () => {
                              trigger("error");
                            },
                          },
                        );
                      }}
                    />
                  ))}
                </ul>
              )}
            </UploadDropZone>
          </CardContent>
        </Card>
      </div>

      <MoveDialog
        open={moveOpen}
        onOpenChange={(o) => setMoveOpen(o)}
        currentPath={currentPath}
        ids={Array.from(selectedIds)}
        onConfirm={async (path) => {
          const ids = Array.from(selectedIds);
          if (ids.length === 0) return;
          trigger("light");
          await move.mutateAsync(
            { ids, path },
            {
              onSuccess: ({ count }) => {
                trigger("success");
                toast.success(t("admin:assets.movedSuccess", { count }));
                setSelectedIds(new Set());
                setMoveOpen(false);
              },
              onError: () => {
                trigger("error");
              },
            },
          );
        }}
      />

      <ConfirmDeleteDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={t("admin:assets.deleteSelectedTitle", { count: selectedIds.size })}
        description={t("admin:assets.deleteSelectedDescription")}
        confirmToken={t("admin:assets.deleteToken", { count: selectedIds.size })}
        typePrompt={t("admin:assets.typePhraseToConfirm")}
        copyAriaLabel={t("admin:assets.copyPhraseAriaLabel")}
        isPending={remove.isPending}
        disabled={selectedIds.size === 0}
        onConfirm={async () => {
          const ids = Array.from(selectedIds);
          if (ids.length === 0) return;
          trigger("warning");
          const results = await Promise.allSettled(ids.map((id) => remove.mutateAsync({ id })));
          const { successCount, failureCount } = getSettledSummary(results);
          if (successCount > 0) {
            trigger("success");
            toast.success(t("admin:assets.deletedSuccess", { count: successCount }));
          }
          if (failureCount > 0) {
            trigger("error");
            toast.error(t("admin:assets.deleteFailed", { count: failureCount }));
          }
          if (failureCount === 0) {
            setSelectedIds(new Set());
            setDeleteOpen(false);
            return;
          }
          const failedIds = ids.filter((_, index) => results[index]?.status === "rejected");
          setSelectedIds(new Set(failedIds));
        }}
      />

      <ConfirmDeleteDialog
        open={!!singleDelete}
        onOpenChange={(o) => {
          if (!o) {
            setSingleDelete(null);
            setSelectedIds(new Set());
          }
        }}
        title={t("admin:assets.singleDeleteTitle")}
        description={
          singleDelete
            ? t("admin:assets.singleDeleteDescriptionNamed", { mimeType: singleDelete.mimeType })
            : t("admin:assets.singleDeleteDescriptionUnnamed")
        }
        confirmToken={singleDelete?.id ?? ""}
        typePrompt={t("admin:assets.typeAssetIdToConfirm")}
        copyAriaLabel={t("admin:assets.copyAssetIdAriaLabel")}
        isPending={remove.isPending}
        onConfirm={async () => {
          if (!singleDelete) return;
          trigger("warning");
          await remove.mutateAsync(
            { id: singleDelete.id },
            {
              onSuccess: () => {
                trigger("success");
                toast.success(t("admin:assets.singleDeleted"));
                setSingleDelete(null);
                setSelectedIds(new Set());
              },
              onError: (error) => {
                trigger("error");
                toast.error(friendly(error, t("admin:assets.singleDeleteFailed")));
              },
            },
          );
        }}
      />
    </div>
  );
}

function FolderTreeView({
  node,
  currentPath,
  onSelect,
  depth = 0,
}: {
  node: FolderNode;
  currentPath: string | null;
  onSelect: (path: string | null) => void;
  depth?: number;
}) {
  const isActive = currentPath === node.path;
  const Icon = node.path === null ? FolderRoot : Folder;
  return (
    <div>
      <button
        type="button"
        onClick={() => onSelect(node.path)}
        className={cn(
          "flex min-h-[44px] w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm",
          isActive ? "bg-muted text-foreground" : "text-muted-foreground hover:bg-muted/50",
        )}
        style={{ paddingLeft: `${depth * 12 + 8}px` }}
      >
        <Icon aria-hidden className="size-4 shrink-0" />
        <span className="truncate">{node.name}</span>
        {node.count > 0 && (
          <span className="ml-auto text-[11px] tabular-nums text-muted-foreground/70">
            {node.count}
          </span>
        )}
      </button>
      {node.children.length > 0 && (
        <div>
          {node.children.map((child) => (
            <FolderTreeView
              key={child.path ?? "root"}
              node={child}
              currentPath={currentPath}
              onSelect={onSelect}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function Breadcrumb({
  segments,
  onSelect,
}: {
  segments: { path: string | null; name: string }[];
  onSelect: (path: string | null) => void;
}) {
  const { t } = useTranslation("admin");
  return (
    <nav
      aria-label={t("assets.breadcrumbAriaLabel")}
      className="mt-1 flex flex-wrap items-center gap-1 text-xs"
    >
      {segments.map((seg, i) => (
        <span key={seg.path ?? "root"} className="flex items-center gap-1">
          {i > 0 && <ChevronRight aria-hidden className="size-3 text-muted-foreground" />}
          <button
            type="button"
            onClick={() => onSelect(seg.path)}
            className={cn(
              "inline-flex min-h-[44px] items-center rounded px-2 hover:bg-muted",
              i === segments.length - 1 ? "font-medium text-foreground" : "text-muted-foreground",
            )}
          >
            {seg.name}
          </button>
        </span>
      ))}
    </nav>
  );
}

function AssetCard({
  asset,
  selected,
  onSelect,
  onDelete,
  onMove,
  onSetVisibility,
}: {
  asset: AssetItem;
  selected: boolean;
  onSelect: (e: { shiftKey: boolean; metaKey: boolean; ctrlKey: boolean }) => void;
  onDelete: () => void;
  onMove: () => void;
  onSetVisibility: (next: "PUBLIC" | "RESTRICTED") => void;
}) {
  const isPublic = asset.visibility === "PUBLIC";
  const { t } = useTranslation("admin");
  return (
    <li className="relative">
      <button
        type="button"
        onClick={(e) => onSelect({ shiftKey: e.shiftKey, metaKey: e.metaKey, ctrlKey: e.ctrlKey })}
        className={cn(
          "group block w-full overflow-hidden rounded-lg border bg-muted text-left",
          selected && "ring-2 ring-primary ring-offset-1",
        )}
      >
        <div className="aspect-square w-full">
          {asset.imageUrl ? (
            <img
              src={`${asset.imageUrl}?w=240&h=240&format=webp`}
              alt=""
              loading="lazy"
              className="h-full w-full object-cover"
            />
          ) : (
            <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
              {asset.mimeType.split("/")[1] ?? t("assets.card.filePlaceholder")}
            </div>
          )}
        </div>
        <div className="border-t bg-background px-2 py-1.5">
          <p className="truncate text-xs font-medium">{asset.id}</p>
          <p className="truncate text-[11px] text-muted-foreground">
            {asset.mimeType} · {(asset.size / 1024).toFixed(0)} KB
          </p>
        </div>
      </button>
      <div className="pointer-events-none absolute left-1 top-1">
        <span
          className={cn(
            "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium backdrop-blur",
            isPublic
              ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
              : "bg-background/80 text-muted-foreground",
          )}
          title={isPublic ? t("assets.card.publicTitle") : t("assets.card.restrictedTitle")}
        >
          {isPublic ? (
            <Eye aria-hidden className="size-3" />
          ) : (
            <EyeOff aria-hidden className="size-3" />
          )}
          {isPublic ? t("assets.card.publicLabel") : t("assets.card.restrictedLabel")}
        </span>
      </div>
      <div className="absolute right-1 top-1">
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button
                variant="secondary"
                size="icon-sm"
                className="min-h-[44px] min-w-[44px] bg-background/80 backdrop-blur"
                aria-label={t("assets.card.actionsAriaLabel")}
              />
            }
          >
            <MoreVertical aria-hidden className="size-4" />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => onSetVisibility(isPublic ? "RESTRICTED" : "PUBLIC")}>
              {isPublic ? t("assets.card.makeRestricted") : t("assets.card.makePublic")}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={onMove}>{t("assets.card.moveAction")}</DropdownMenuItem>
            <DropdownMenuItem onClick={onDelete}>{t("assets.card.deleteAction")}</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </li>
  );
}

function UploadDropZone({
  onFiles,
  disabled,
  children,
}: {
  onFiles: (files: File[]) => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  const [active, setActive] = useState(false);
  return (
    <div
      onDragOver={(e) => {
        if (disabled) return;
        e.preventDefault();
        setActive(true);
      }}
      onDragLeave={(e) => {
        if (e.currentTarget.contains(e.relatedTarget as Node)) return;
        setActive(false);
      }}
      onDrop={(e) => {
        if (disabled) return;
        e.preventDefault();
        setActive(false);
        const files = Array.from(e.dataTransfer.files);
        if (files.length) onFiles(files);
      }}
      className="relative"
    >
      {children}
      {active && <DropOverlay />}
    </div>
  );
}

function DropOverlay() {
  const { t } = useTranslation("admin");
  return (
    <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-md border-2 border-dashed border-primary bg-primary/5 text-primary">
      <div className="flex flex-col items-center gap-2">
        <Upload className="size-6" />
        <span className="text-sm font-medium">{t("assets.dropToUpload")}</span>
      </div>
    </div>
  );
}

function GridSkeleton() {
  return (
    <ul className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5">
      {Array.from({ length: 10 }).map((_, i) => (
        <li key={`asset-skel-${i}`}>
          <Skeleton className="aspect-square w-full rounded-lg" />
          <Skeleton className="mt-2 h-3 w-2/3" />
        </li>
      ))}
    </ul>
  );
}

const PATH_REGEX = /^\/(?:[A-Za-z0-9_-]+\/)*$/;

function MoveDialog({
  open,
  onOpenChange,
  currentPath,
  ids,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  currentPath: string | null;
  ids: string[];
  onConfirm: (path: string | null) => Promise<void> | void;
}) {
  const inputId = useId();
  const [destination, setDestination] = useState<string>("");
  const { t } = useTranslation(["admin", "common"]);
  const value = open ? destination || currentPath || "" : "";
  const trimmed = value.trim();
  const isRoot = trimmed === "" || trimmed === "/";
  const valid = isRoot || PATH_REGEX.test(trimmed);
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        onOpenChange(o);
        if (!o) setDestination("");
        else setDestination(currentPath ?? "");
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("admin:assets.moveDialogTitle", { count: ids.length })}</DialogTitle>
          <DialogDescription>
            <Trans
              i18nKey="assets.moveDescription"
              t={t}
              components={[<code key="0" />, <code key="1" />]}
            />
          </DialogDescription>
        </DialogHeader>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (!valid) return;
            const next = isRoot ? null : trimmed;
            await onConfirm(next);
          }}
          className="space-y-3 px-4 sm:px-6"
        >
          <div className="space-y-2">
            <Label htmlFor={inputId}>{t("admin:assets.destinationPath")}</Label>
            <Input
              id={inputId}
              value={value}
              onChange={(e) => setDestination(e.target.value)}
              placeholder="/images/"
              autoComplete="off"
            />
            {!valid && (
              <p className="text-sm text-destructive">
                <Trans i18nKey="assets.pathFormatError" t={t} components={[<code key="0" />]} />
              </p>
            )}
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              className="min-h-[44px]"
            >
              {t("common:actions.cancel")}
            </Button>
            <Button type="submit" disabled={!valid || ids.length === 0} className="min-h-[44px]">
              {t("admin:assets.move")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
