import prisma from "@flycockpit/db";
import { cleanupAssetsQueue } from "@flycockpit/queue";
import { ORPCError } from "@orpc/server";
import { z } from "zod";

import { adminOr404Procedure } from "../index";
import { dryRunCleanup } from "../lib/asset-cleanup";
import { deleteStorageObject } from "../lib/storage";

const idSchema = z.string().min(1);

const pathSchema = z
  .string()
  .max(512)
  .regex(/^\/(?:[A-Za-z0-9_-]+\/)*$/, "Path must start and end with /, e.g. /images/blog/")
  .nullable();

function isUniqueConstraintError(err: unknown): boolean {
  return typeof err === "object" && err !== null && "code" in err && err.code === "P2002";
}

type AssetRow = {
  id: string;
  createdAt: Date;
  updatedAt: Date;
  storageKey: string;
  mimeType: string;
  size: bigint | number;
  visibility: { toString(): string } | string;
  ownerId: string | null;
  width: number | null;
  height: number | null;
  blurhash: string | null;
  // After the Folder normalization, Asset rows carry `folderId` + an optional
  // hydrated `Folder` relation. The serialized shape still exposes a `path`
  // string so the admin Finder UI (and MCP tools) need no changes.
  Folder?: { path: string } | null;
};

/**
 * Derive a human-readable label for an asset. Honors the autosuggest contract
 * ("IDs travel, names display"): the result MUST differ from `asset.id` so the
 * `AsyncCombobox` trigger never renders a bare id. The `AsyncCombobox` dev-mode
 * warn (`getKey(value) === getLabel(value)`) is the safety net if this ever
 * regresses. There is no `fileName` column yet, so we synthesize from what we
 * have, in order of usefulness:
 *   1. basename of `storageKey` if it looks file-like (`name.ext`),
 *   2. else mimeType + dimensions when present (e.g. `image/png · 640×480`),
 *   3. else a short id suffix prefixed with `…` (never the bare id).
 */
function deriveAssetLabel(asset: AssetRow): string {
  const basename = asset.storageKey.split("/").pop() ?? "";
  if (/.+\.\w{1,5}$/.test(basename)) {
    return basename;
  }
  const hasDimensions = asset.width != null && asset.height != null;
  if (hasDimensions) {
    return `${asset.mimeType} · ${asset.width}×${asset.height}`;
  }
  // Fallback: short suffix of the id, distinct from the bare id by the `…`.
  return `…${asset.id.slice(-7)}`;
}

/**
 * Serializes an Asset row for admin consumption.
 *
 * Agent rule note: every URL emitted here is a 24h bearer token. The
 * `listByPath` procedure that calls this is `adminOr404` — only admins ever
 * see these URLs. If a non-admin variant is added later, it must filter by
 * the same predicate `canViewAsset()` uses.
 */
function serializeAsset(asset: AssetRow) {
  return {
    id: asset.id,
    createdAt: asset.createdAt,
    updatedAt: asset.updatedAt,
    mimeType: asset.mimeType,
    size: Number(asset.size),
    visibility: String(asset.visibility),
    ownerId: asset.ownerId,
    width: asset.width,
    height: asset.height,
    blurhash: asset.blurhash,
    label: deriveAssetLabel(asset),
    path: asset.Folder?.path ?? null,
    url: `/api/assets/${asset.id}`,
    imageUrl: asset.mimeType.startsWith("image/") ? `/api/images/${asset.id}` : null,
  };
}

/**
 * Resolve a path string to a `folderId` filter clause.
 *   path === null      → "root assets" (folderId is null)
 *   path === "/foo/"   → folderId equals the Folder row with that path, or
 *                        a sentinel that matches no rows when the folder
 *                        doesn't exist yet (avoids returning the entire root
 *                        list as a false-positive empty-folder).
 */
async function resolvePathFilter(path: string | null): Promise<{ folderId: string | null }> {
  if (path === null) return { folderId: null };
  const folder = await prisma.folder.findUnique({ where: { path }, select: { id: true } });
  // No folder exists at this path yet → the filter must match zero rows, not
  // every root-level row. An impossible id string is the simplest safe sentinel.
  return { folderId: folder?.id ?? "__no_such_folder__" };
}

export const assetsRouter = {
  /**
   * Folder-style listing — filters Asset rows whose folder matches the
   * provided path (null = root). Pages are cursor-based to avoid expensive
   * OFFSET scans on large libraries.
   */
  listByPath: adminOr404Procedure
    .input(
      z
        .object({
          path: pathSchema.default(null),
          limit: z.number().min(1).max(100).default(50),
          cursor: idSchema.optional(),
        })
        .optional(),
    )
    .handler(async ({ input }) => {
      const path = input?.path ?? null;
      const limit = input?.limit ?? 50;
      const cursor = input?.cursor;
      const where = await resolvePathFilter(path);
      const items = await prisma.asset.findMany({
        where,
        include: { Folder: true },
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        take: limit + 1,
        ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
      });
      const hasMore = items.length > limit;
      const slice = hasMore ? items.slice(0, limit) : items;
      return {
        items: slice.map(serializeAsset),
        nextCursor: hasMore ? (slice[slice.length - 1]?.id ?? null) : null,
      };
    }),

  /**
   * Flip an asset between PUBLIC and RESTRICTED. The cache header on the next
   * fetch reflects the new value immediately, but a CDN may still serve the
   * previous bytes for up to 24 h after a PUBLIC → RESTRICTED downgrade.
   */
  setVisibility: adminOr404Procedure
    .input(
      z.object({
        id: idSchema,
        visibility: z.enum(["PUBLIC", "RESTRICTED"]),
      }),
    )
    .handler(async ({ input }) => {
      const existing = await prisma.asset.findUnique({ where: { id: input.id } });
      if (!existing) throw new ORPCError("NOT_FOUND", { message: "Asset not found" });
      const updated = await prisma.asset.update({
        where: { id: input.id },
        data: { visibility: input.visibility },
        include: { Folder: true },
      });
      return serializeAsset(updated);
    }),

  /**
   * Move one or many assets to a new path (or to root with `path: null`).
   * Folders are upserted lazily — the first move into a path creates the
   * Folder row, subsequent moves reuse it. Returns the count of rows
   * actually updated.
   */
  move: adminOr404Procedure
    .input(
      z.object({
        ids: z.array(idSchema).min(1).max(500),
        path: pathSchema,
      }),
    )
    .handler(async ({ input }) => {
      // Resolve the destination folderId before the bulk update. Root moves
      // skip the upsert entirely (folderId: null = root).
      let folderId: string | null = null;
      if (input.path !== null) {
        const folder = await prisma.folder
          .upsert({
            where: { path: input.path },
            create: { path: input.path },
            update: {},
            select: { id: true },
          })
          .catch((err) => {
            if (isUniqueConstraintError(err)) {
              throw new ORPCError("CONFLICT", { message: "That folder was created concurrently." });
            }
            throw err;
          });
        folderId = folder.id;
      }
      const result = await prisma.asset.updateMany({
        where: { id: { in: input.ids } },
        data: { folderId },
      });
      return { count: result.count };
    }),

  /**
   * Distinct list of folder paths currently in use. Drives the folder tree in
   * the admin Finder UI. Returns the same `{ path, count }` shape the UI
   * expected when this was a `groupBy` over `Asset.path` — including a
   * synthetic row for root (`path: null`) covering folder-less assets.
   */
  listPaths: adminOr404Procedure.handler(async () => {
    const [folders, rootCount] = await Promise.all([
      prisma.folder.findMany({
        orderBy: { path: "asc" },
        include: { _count: { select: { Assets: true } } },
      }),
      prisma.asset.count({ where: { folderId: null } }),
    ]);
    const out: { path: string | null; count: number }[] = [];
    if (rootCount > 0) out.push({ path: null, count: rootCount });
    for (const f of folders) {
      out.push({ path: f.path, count: f._count.Assets });
    }
    return out;
  }),

  /**
   * Cross-folder recent list — used by the overview thumbnail strip. Avoids
   * the `listByPath` constraint that filters to a single folder.
   */
  recent: adminOr404Procedure
    .input(z.object({ limit: z.number().min(1).max(50).default(8) }).optional())
    .handler(async ({ input }) => {
      const limit = input?.limit ?? 8;
      const items = await prisma.asset.findMany({
        include: { Folder: true },
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        take: limit,
      });
      return { items: items.map(serializeAsset) };
    }),

  /**
   * Recent image-only asset list for the hero-image picker combobox.
   * Restricted to image/* so the picker only surfaces renderables.
   */
  search: adminOr404Procedure
    .input(
      z.object({
        query: z.string().max(120).default(""),
        limit: z.number().min(1).max(50).default(10),
        publicOnly: z.boolean().default(false),
      }),
    )
    .handler(async ({ input }) => {
      const items = await prisma.asset.findMany({
        where: {
          mimeType: { startsWith: "image/" },
          ...(input.publicOnly ? { visibility: "PUBLIC" } : {}),
        },
        include: { Folder: true },
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        take: input.limit,
      });
      return items.map(serializeAsset);
    }),

  /**
   * Delete an asset row and its underlying storage object. We delete the row
   * first so a half-deleted state can never serve stale bytes from S3 after
   * the row is gone; if storage delete fails we log and continue (orphan
   * cleanup is the caller's problem at that point).
   */
  delete: adminOr404Procedure.input(z.object({ id: idSchema })).handler(async ({ input }) => {
    const asset = await prisma.asset.findUnique({ where: { id: input.id } });
    if (!asset) throw new ORPCError("NOT_FOUND", { message: "Asset not found" });
    await prisma.asset.delete({ where: { id: input.id } });
    try {
      await deleteStorageObject(asset.storageKey);
    } catch (err) {
      console.error("[assets] storage delete failed", { id: input.id, err });
    }
    return { success: true };
  }),

  /**
   * Inspect what the cleanup job would do — counts, totals, and a sample of
   * each category. Runs synchronously since a dry run is read-only; the
   * destructive sweep is always enqueued via `cleanupEnqueue`.
   */
  cleanupDryRun: adminOr404Procedure.handler(async () => {
    const summary = await dryRunCleanup();
    return {
      pendingRows: summary.pendingRows,
      orphanObjects: summary.orphanObjects,
      incompleteMultipart: summary.incompleteMultipart,
    };
  }),

  /**
   * Enqueue the same job the 24h cron uses. Returns the BullMQ job id so the
   * UI can poll for completion via `queue.getJob`.
   */
  cleanupEnqueue: adminOr404Procedure.handler(async () => {
    const job = await cleanupAssetsQueue.add("cleanup-assets", { reason: "admin" });
    return { jobId: job.id ?? null };
  }),
};
