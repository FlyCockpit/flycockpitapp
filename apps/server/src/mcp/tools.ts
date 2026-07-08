import { appRouter } from "@flycockpit/api/routers/index";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createRouterClient, ORPCError } from "@orpc/server";
import * as z from "zod/v4";

import { isAllowedUploadMimeType } from "../upload-mime.js";
import { getMcpContext } from "./auth";

function getCallableRouter() {
  const ctx = getMcpContext();
  return createRouterClient(appRouter, {
    context: { session: ctx.session },
  });
}

function toolError(message: string) {
  return {
    content: [{ type: "text" as const, text: `Error: ${message}` }],
    isError: true,
  };
}

function ok(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function requireMcpWriteScope() {
  const scope = getMcpContext().session.mcpApiKeyScope;
  if (scope === "read") {
    throw new ORPCError("FORBIDDEN", { message: "This MCP API key is read-only" });
  }
}

async function safe<T>(fn: () => Promise<T>, options: { write?: boolean } = {}) {
  try {
    if (options.write) requireMcpWriteScope();
    return ok(await fn());
  } catch (err) {
    if (err instanceof ORPCError) {
      return toolError(`${err.code}: ${err.message}`);
    }
    return toolError(err instanceof Error ? err.message : String(err));
  }
}

const assetPathSchema = z
  .string()
  .max(512)
  .regex(/^\/(?:[A-Za-z0-9_-]+\/)*$/)
  .nullable();

export function registerTools(server: McpServer): void {
  server.registerTool(
    "assets_list",
    {
      title: "List assets",
      description: "List assets in a folder. Pass null path for root.",
      inputSchema: {
        path: assetPathSchema.optional(),
        limit: z.number().int().min(1).max(100).optional(),
        cursor: z.string().optional(),
      },
    },
    async (input) =>
      safe(() =>
        getCallableRouter().assets.listByPath({
          path: input.path ?? null,
          limit: input.limit ?? 50,
          cursor: input.cursor,
        }),
      ),
  );

  server.registerTool(
    "assets_upload",
    {
      title: "Upload asset",
      description: "Upload an asset from a base64 body.",
      inputSchema: {
        filename: z.string().min(1).max(255),
        mimeType: z.string().min(1).max(255),
        bodyBase64: z.string().min(1),
        visibility: z.enum(["PUBLIC", "RESTRICTED"]).optional(),
        path: assetPathSchema.optional(),
      },
    },
    async ({ filename, mimeType, bodyBase64, visibility, path }) =>
      safe(
        async () => {
          const bytes = new Uint8Array(Buffer.from(bodyBase64, "base64"));
          if (bytes.byteLength === 0) {
            throw new ORPCError("BAD_REQUEST", { message: "bodyBase64 is empty" });
          }
          if (!isAllowedUploadMimeType(mimeType)) {
            throw new ORPCError("BAD_REQUEST", { message: "File type is not allowed." });
          }

          const ctx = getMcpContext();
          const { createAsset } = await import("@flycockpit/api/lib/assets");
          const { analyzeImage } = await import("@flycockpit/api/lib/images");
          const analysis = mimeType.startsWith("image/")
            ? await analyzeImage(bytes, mimeType)
            : null;

          const asset = await createAsset({
            body: bytes,
            mimeType,
            visibility: visibility ?? "RESTRICTED",
            ownerId: ctx.session.user.id,
            width: analysis?.width ?? null,
            height: analysis?.height ?? null,
            blurhash: analysis?.blurhash ?? null,
          });

          if (path) {
            await getCallableRouter().assets.move({ ids: [asset.id], path });
          }
          return { ...asset, filename, path: path ?? null };
        },
        { write: true },
      ),
  );

  server.registerTool(
    "assets_move",
    {
      title: "Move assets",
      description: "Move one or many assets to a folder path, or null for root.",
      inputSchema: {
        ids: z.array(z.string()).min(1).max(500),
        path: assetPathSchema,
      },
    },
    async ({ ids, path }) =>
      safe(() => getCallableRouter().assets.move({ ids, path }), { write: true }),
  );

  server.registerTool(
    "assets_delete",
    {
      title: "Delete asset",
      description: "Delete an asset row and its underlying storage object.",
      inputSchema: { id: z.string() },
    },
    async ({ id }) => safe(() => getCallableRouter().assets.delete({ id }), { write: true }),
  );
}
