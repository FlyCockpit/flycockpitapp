import { isIP } from "node:net";
import { env } from "@flycockpit/env/server";
import { getConnInfo } from "@hono/node-server/conninfo";
import type { Context } from "hono";
import { isPrivateIp } from "./private-ip.js";

/**
 * Resolve the real client IP for an anonymous request, accounting for reverse
 * proxies. This is the rate-limit key for traffic that isn't tied to a user id.
 *
 * The TCP socket peer (`getConnInfo`) is the real client ONLY when the app is
 * exposed directly to the internet. Every deploy target in our docs (Render,
 * Railway, Dokploy/nginx, Azure Container Apps) terminates TLS at a reverse
 * proxy and forwards to the app over a private network — so the socket peer is
 * the proxy, and the client IP lives in `X-Forwarded-For`.
 *
 * `X-Forwarded-For` is `<client-supplied>, <appended by hop 1>, <hop 2>, ...`.
 * The LEFTMOST entry is whatever the client sent (forgeable — keying on it was
 * the original CVE). Each trusted proxy APPENDS the address it received the
 * request from, so the address written by the proxy nearest the app is the
 * rightmost one we should trust.
 *
 * Default (TRUST_PROXY_HOPS unset) — zero config, correct for every documented
 * target: walk the `[...X-Forwarded-For, socketPeer]` chain from the right and
 * return the first address that is NOT in a private/loopback/CGNAT range. Those
 * private hops are our own infra (the proxy ⇄ app private network); the first
 * public address is the real client, and it was written by a trusted proxy, so
 * it can't be spoofed by the client. On a bare deployment the socket peer is
 * itself public and is returned directly, so a forged `X-Forwarded-For` is
 * ignored. In local dev there is no `X-Forwarded-For` and the loopback socket
 * peer is used.
 *
 * Escape hatch (TRUST_PROXY_HOPS = N) — for a proxy with a PUBLIC IP (e.g.
 * Cloudflare) or any fixed topology where the heuristic can't tell infra from
 * client: take the entry exactly N hops from the right. N = 0 always keys on
 * the socket peer and ignores `X-Forwarded-For`.
 */
export function resolveClientIp(c: Context): string {
  const socket = getConnInfo(c).remote.address;
  const forwarded = (c.req.header("x-forwarded-for") ?? "")
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);

  // Hop chain, client-first: X-Forwarded-For entries, then the real socket peer.
  const chain = [...forwarded, ...(socket ? [socket] : [])];
  if (chain.length === 0) return "unknown";

  const hops = env.TRUST_PROXY_HOPS;
  if (hops !== undefined) {
    // Explicit topology: the client is `hops` entries from the right.
    return chain[chain.length - 1 - hops] ?? chain[0] ?? "unknown";
  }

  // Zero-config: the first public (non-infra) address from the right.
  for (let i = chain.length - 1; i >= 0; i--) {
    const ip = chain[i];
    if (ip && !isTrustedHop(ip)) return ip;
  }

  // Every hop is private (e.g. fully internal traffic) — key on the leftmost.
  return chain[0] ?? "unknown";
}

/**
 * A hop is "trusted" (our own infra, to be skipped over) when it is a valid IP
 * literal in a private/loopback/link-local/CGNAT range. A non-IP value (a
 * malformed/spoofed token) is NOT trusted, so it is returned rather than
 * silently skipped — keying on a garbage value still rate-limits the sender.
 */
function isTrustedHop(address: string): boolean {
  const version = isIP(address);
  if (version === 0) return false;
  return isPrivateIp(address, version);
}
