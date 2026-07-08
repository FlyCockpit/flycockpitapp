import type { Context } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Mutable env so each test can set TRUST_PROXY_HOPS independently.
const mockEnv: { TRUST_PROXY_HOPS: number | undefined } = { TRUST_PROXY_HOPS: undefined };
vi.mock("@flycockpit/env/server", () => ({ env: mockEnv }));

const mockGetConnInfo = vi.fn(() => ({ remote: { address: "10.0.0.1" } }));
vi.mock("@hono/node-server/conninfo", () => ({ getConnInfo: mockGetConnInfo }));

const { resolveClientIp } = await import("./client-ip.js");

function ctx(opts: { socket?: string; xff?: string }): Context {
  mockGetConnInfo.mockReturnValue({ remote: { address: opts.socket ?? "" } });
  return {
    req: {
      header: (name: string) => (name.toLowerCase() === "x-forwarded-for" ? opts.xff : undefined),
    },
  } as unknown as Context;
}

describe("resolveClientIp (heuristic, TRUST_PROXY_HOPS unset)", () => {
  beforeEach(() => {
    mockEnv.TRUST_PROXY_HOPS = undefined;
  });

  it("uses the loopback socket peer in local dev (no X-Forwarded-For)", () => {
    expect(resolveClientIp(ctx({ socket: "127.0.0.1" }))).toBe("127.0.0.1");
  });

  it("returns the public socket peer directly on a bare deployment", () => {
    // Forged X-Forwarded-For must be ignored when the socket peer is public.
    expect(resolveClientIp(ctx({ socket: "198.51.100.50", xff: "203.0.113.1" }))).toBe(
      "198.51.100.50",
    );
  });

  it("trusts the proxy-appended client IP behind a private-network proxy", () => {
    // socket = proxy (private); proxy appended the real client on the right.
    expect(resolveClientIp(ctx({ socket: "10.0.0.5", xff: "203.0.113.9, 198.51.100.7" }))).toBe(
      "198.51.100.7",
    );
  });

  it("is not fooled by a spoofed public leftmost entry", () => {
    // Client sets a fake left entry; the proxy appends the truth on the right.
    expect(resolveClientIp(ctx({ socket: "10.0.0.5", xff: "8.8.8.8, 198.51.100.7" }))).toBe(
      "198.51.100.7",
    );
  });

  it("skips malformed/garbage hops but still keys on a deterministic value", () => {
    // A non-IP token is untrusted and returned (keying on garbage still limits
    // the sender) rather than silently skipped to a value it controls.
    expect(resolveClientIp(ctx({ socket: "10.0.0.5", xff: "not-an-ip" }))).toBe("not-an-ip");
  });

  it("falls back to the leftmost hop when every hop is private", () => {
    expect(resolveClientIp(ctx({ socket: "10.0.0.5", xff: "10.0.0.9" }))).toBe("10.0.0.9");
  });

  it("returns 'unknown' when there is no socket peer and no header", () => {
    expect(resolveClientIp(ctx({ socket: "" }))).toBe("unknown");
  });

  it("ignores IPv6 ULA/link-local proxy hops", () => {
    expect(resolveClientIp(ctx({ socket: "fd00::1", xff: "2001:db8::5" }))).toBe("2001:db8::5");
  });
});

describe("resolveClientIp (explicit TRUST_PROXY_HOPS)", () => {
  it("takes the Nth-from-right entry for a public proxy (e.g. Cloudflare)", () => {
    // One public-IP proxy: the socket peer is the CDN (104.16.0.1) and the
    // client is the rightmost X-Forwarded-For entry. The heuristic would
    // wrongly stop at the public CDN address; HOPS=1 points at the true client.
    mockEnv.TRUST_PROXY_HOPS = 1;
    expect(resolveClientIp(ctx({ socket: "104.16.0.1", xff: "198.51.100.7" }))).toBe(
      "198.51.100.7",
    );
  });

  it("HOPS=0 always keys on the socket peer and ignores X-Forwarded-For", () => {
    mockEnv.TRUST_PROXY_HOPS = 0;
    expect(resolveClientIp(ctx({ socket: "10.0.0.5", xff: "8.8.8.8, 198.51.100.7" }))).toBe(
      "10.0.0.5",
    );
  });

  it("clamps an over-large hop count to the leftmost entry", () => {
    mockEnv.TRUST_PROXY_HOPS = 9;
    expect(resolveClientIp(ctx({ socket: "10.0.0.5", xff: "203.0.113.9" }))).toBe("203.0.113.9");
  });
});
