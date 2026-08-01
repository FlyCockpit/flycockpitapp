# MCP connection approvals

Cockpit authorizes an external MCP server before it is connected. This happens on first use, not while `.cockpit/mcp.json` is discovered, so configured servers do not prompt until a search, description lookup, or invocation needs them.

A stdio approval displays and keys on the server name, resolved command, and complete argument list. A remote approval displays and keys on the server name, transport, and exact endpoint. Header and environment credentials are never included in the approval identity. Changing a command, argument, or endpoint therefore requires a fresh connection approval.

Connection approval is separate from external MCP tool approval. After a server is approved and connected, each external tool still requires its own exact `(server, tool)` approval. In yolo mode connection approval is the explicit unattended opt-in; otherwise a missing approval client fails closed before a child process is spawned or a remote connection is attempted.
