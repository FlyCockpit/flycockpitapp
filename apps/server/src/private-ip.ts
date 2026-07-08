// Shared private/non-routable IP predicates.
//
// Used both by the external-image SSRF guard (asset-routes.ts) — where a
// private result means "refuse to fetch" — and by the client-IP resolver
// (client-ip.ts) — where a private result means "this hop is our own infra, a
// trusted proxy, not the real client."
//
// Both callers fail closed: anything we can't positively classify as public is
// treated as private. The IPv6 path unwraps IPv4-mapped addresses
// (::ffff:a.b.c.d) and reuses the IPv4 predicate so the two never drift.

import { isIP } from "node:net";

export function isPrivateIp(address: string, family: number): boolean {
  if (family === 4) return isPrivateIpv4(address);
  if (family === 6) return isPrivateIpv6(address);
  return true;
}

function isPrivateIpv4(address: string): boolean {
  const parts = address.split(".").map((part) => Number.parseInt(part, 10));
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return true;
  }
  const a = parts[0];
  const b = parts[1];
  if (a === undefined || b === undefined) return true;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isPrivateIpv6(address: string): boolean {
  // Drop a zone id (fe80::1%eth0) before any comparison.
  const zoneIndex = address.indexOf("%");
  const normalized = (zoneIndex === -1 ? address : address.slice(0, zoneIndex)).toLowerCase();

  // IPv4-mapped (::ffff:a.b.c.d / ::ffff:xxxx:xxxx) and the deprecated
  // IPv4-compatible (::a.b.c.d) forms carry a real IPv4 destination. Unwrap and
  // run the IPv4 predicate so e.g. ::ffff:169.254.169.254 is blocked.
  const embedded = embeddedIpv4(normalized);
  if (embedded !== null) return isPrivateIpv4(embedded);

  if (normalized === "::" || normalized === "::1") return true;

  // Unique-local fc00::/7 (fc.. and fd..).
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;

  // Link-local fe80::/10 — the whole fe80::–febf:: span, not just fe80:.
  const firstHextet = firstHextetValue(normalized);
  if (firstHextet !== null && firstHextet >= 0xfe80 && firstHextet <= 0xfebf) {
    return true;
  }

  return false;
}

// Recognize an IPv4 address embedded in an IPv6 literal and return it in dotted
// form, or null if there is none. Handles the dotted mapped/compatible forms
// (...:a.b.c.d) and the all-hex mapped form (::ffff:xxxx:xxxx).
function embeddedIpv4(addr: string): string | null {
  const lastColon = addr.lastIndexOf(":");
  if (lastColon !== -1) {
    const tail = addr.slice(lastColon + 1);
    if (tail.includes(".")) return isIP(tail) === 4 ? tail : null;
  }

  if (addr.startsWith("::ffff:")) {
    const groups = addr.slice(2).split(":"); // ["ffff", "xxxx", "xxxx"]
    if (groups.length === 3 && groups[0] === "ffff") {
      const hi = Number.parseInt(groups[1] ?? "", 16);
      const lo = Number.parseInt(groups[2] ?? "", 16);
      if (
        Number.isInteger(hi) &&
        Number.isInteger(lo) &&
        hi >= 0 &&
        hi <= 0xffff &&
        lo >= 0 &&
        lo <= 0xffff
      ) {
        return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
      }
    }
  }

  return null;
}

// Value of the first 16-bit group, used for the link-local range test. A
// leading "::" compresses the first group to zero.
function firstHextetValue(addr: string): number | null {
  if (addr.startsWith("::")) return 0;
  const firstGroup = addr.split(":")[0];
  if (!firstGroup) return null;
  const value = Number.parseInt(firstGroup, 16);
  return Number.isInteger(value) ? value : null;
}
