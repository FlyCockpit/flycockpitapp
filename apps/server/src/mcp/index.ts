import { randomUUID } from "node:crypto";
import { StreamableHTTPTransport } from "@hono/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { type Context, Hono } from "hono";

import { mcpAuthMiddleware } from "./auth";
import { registerTools } from "./tools";

type McpSession = {
  transport: StreamableHTTPTransport;
};

const sessions = new Map<string, McpSession>();
const MAX_MCP_SESSIONS = 100;

function rememberSession(id: string, entry: McpSession): void {
  if (!sessions.has(id) && sessions.size >= MAX_MCP_SESSIONS) {
    const oldestId = sessions.keys().next().value;
    if (oldestId) sessions.delete(oldestId);
  }
  sessions.set(id, entry);
}

async function createSession(): Promise<McpSession> {
  let sessionId: string | undefined;
  const transport = new StreamableHTTPTransport({
    sessionIdGenerator: () => {
      sessionId = randomUUID();
      return sessionId;
    },
    onsessioninitialized: (id) => {
      rememberSession(id, entry);
    },
    onsessionclosed: (id) => {
      sessions.delete(id);
    },
  });
  transport.onclose = () => {
    if (sessionId) sessions.delete(sessionId);
  };

  const server = new McpServer({
    name: "flycockpit-admin-mcp",
    version: "1.0.0",
  });
  registerTools(server);

  const entry = { transport };
  await server.connect(transport);
  return entry;
}

async function getSession(c: Context): Promise<McpSession | null> {
  const sessionId = c.req.header("mcp-session-id");
  if (sessionId) {
    return sessions.get(sessionId) ?? null;
  }
  if (c.req.method === "POST") {
    return createSession();
  }
  return null;
}

// Mounted as a sub-app so the auth middleware is the first thing that runs
// on /mcp; nothing else on the parent app sees the request until the bearer
// token has been resolved to an admin session.
export const mcpApp = new Hono();
mcpApp.all("/", mcpAuthMiddleware, async (c) => {
  const session = await getSession(c);
  if (!session) {
    return c.json(
      {
        jsonrpc: "2.0",
        error: { code: -32000, message: "Session not found" },
        id: null,
      },
      404,
    );
  }
  const response = await session.transport.handleRequest(c);
  // The transport returns Response on most paths; if it streams via SSE it
  // takes over the connection itself and returns undefined. In that case we
  // hand control back to Hono which leaves the context as-is.
  return response ?? c.body(null);
});
