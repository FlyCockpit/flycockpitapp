import type { Context, Next } from "hono";
import { describe, expect, it, vi } from "vitest";

const { transports } = vi.hoisted(() => ({
  transports: [] as Array<{
    id: number;
    handleRequest: (c: Context) => Promise<Response | undefined>;
  }>,
}));

vi.mock("./auth", () => ({
  mcpAuthMiddleware: (_c: Context, next: Next) => next(),
}));

vi.mock("./tools", () => ({
  registerTools: vi.fn(),
}));

vi.mock("@modelcontextprotocol/sdk/server/mcp.js", () => ({
  McpServer: class {
    async connect() {
      return undefined;
    }
  },
}));

vi.mock("@hono/mcp", () => ({
  StreamableHTTPTransport: class {
    id = transports.length + 1;
    options: {
      sessionIdGenerator: () => string;
      onsessioninitialized: (id: string) => void | Promise<void>;
    };

    constructor(options: {
      sessionIdGenerator: () => string;
      onsessioninitialized: (id: string) => void | Promise<void>;
    }) {
      this.options = options;
      transports.push(this);
    }

    async handleRequest(c: Context) {
      const existingSessionId = c.req.header("mcp-session-id");
      if (existingSessionId) {
        return c.json({ transportId: this.id, sessionId: existingSessionId });
      }

      const sessionId = this.options.sessionIdGenerator();
      await this.options.onsessioninitialized(sessionId);
      c.header("mcp-session-id", sessionId);
      return c.json({ transportId: this.id, sessionId });
    }
  },
}));

const { mcpApp } = await import("./index");

describe("mcpApp session transports", () => {
  it("isolates transport state per initialized MCP session", async () => {
    const first = await mcpApp.request("/", { method: "POST" });
    const firstBody = (await first.json()) as { transportId: number; sessionId: string };
    const firstSessionId = first.headers.get("mcp-session-id");

    const second = await mcpApp.request("/", { method: "POST" });
    const secondBody = (await second.json()) as { transportId: number; sessionId: string };
    const secondSessionId = second.headers.get("mcp-session-id");

    expect(firstSessionId).toBe(firstBody.sessionId);
    expect(secondSessionId).toBe(secondBody.sessionId);
    expect(firstSessionId).not.toBe(secondSessionId);
    expect(firstBody.transportId).not.toBe(secondBody.transportId);

    const firstFollowUp = await mcpApp.request("/", {
      method: "GET",
      headers: { "mcp-session-id": firstSessionId ?? "" },
    });
    await expect(firstFollowUp.json()).resolves.toEqual({
      transportId: firstBody.transportId,
      sessionId: firstSessionId,
    });

    const secondFollowUp = await mcpApp.request("/", {
      method: "GET",
      headers: { "mcp-session-id": secondSessionId ?? "" },
    });
    await expect(secondFollowUp.json()).resolves.toEqual({
      transportId: secondBody.transportId,
      sessionId: secondSessionId,
    });
  });

  it("rejects requests for unknown MCP sessions", async () => {
    const response = await mcpApp.request("/", {
      method: "GET",
      headers: { "mcp-session-id": "missing" },
    });

    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toMatchObject({
      error: { message: "Session not found" },
    });
  });
});
