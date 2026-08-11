/**
 * Closed-set Origin class verifier for the remote signaling gateway.
 *
 * Origin classes are closed:
 * - `browser_same_origin` requires exactly the configured HTTPS public origin
 *   with no `null`, alternate port/scheme/subdomain, or multiple Origin.
 * - `native_no_origin` and `daemon_no_origin` require the header be absent and
 *   the ticket/certificate role match.
 *
 * A present Origin can never claim native/daemon; an absent Origin can never
 * claim browser.
 */
import type { RemoteGatewayOriginClass } from "./close-codes";

export interface OriginVerificationResult {
  class: RemoteGatewayOriginClass;
}

export class OriginVerificationError extends Error {}

/**
 * Verify the Origin header against the expected class for a given subprotocol.
 *
 * @param originHeader - the raw `Origin` header value(s), or undefined if absent.
 * @param configuredOrigin - the exact configured HTTPS public origin.
 * @param expectedClass - the Origin class the subprotocol/role demands.
 */
export function verifyOriginClass(
  originHeader: string | string[] | undefined,
  configuredOrigin: string,
  expectedClass: RemoteGatewayOriginClass,
): OriginVerificationResult {
  // Multiple Origin headers → reject. A well-behaved browser sends exactly one.
  if (Array.isArray(originHeader) && originHeader.length > 1) {
    throw new OriginVerificationError("multiple_origin");
  }
  const raw = Array.isArray(originHeader) ? originHeader[0] : originHeader;
  const present = raw !== undefined && raw !== null && raw !== "";

  if (expectedClass === "browser_same_origin") {
    if (!present) throw new OriginVerificationError("absent_origin_browser");
    if (raw === "null") throw new OriginVerificationError("null_origin");
    // Exact match — no alternate port/scheme/subdomain.
    if (raw !== configuredOrigin) throw new OriginVerificationError("origin_mismatch");
    return { class: "browser_same_origin" };
  }

  // native_no_origin and daemon_no_origin: header must be absent.
  if (present) throw new OriginVerificationError("present_origin_native");
  return { class: expectedClass };
}

/**
 * Map a subprotocol to its expected Origin class.
 *
 * The signal subprotocol may be browser or native depending on the ticket's
 * Origin class binding. The control subprotocol is always daemon_no_origin.
 * The data subprotocol follows the same rules as signal.
 */
export function subprotocolExpectedOriginClass(
  subprotocol: string,
  ticketOriginClass?: RemoteGatewayOriginClass,
): RemoteGatewayOriginClass {
  if (subprotocol === "flycockpit.remote-control.v1") return "daemon_no_origin";
  if (
    subprotocol === "flycockpit.remote-signal.v1" ||
    subprotocol === "flycockpit.remote-data.v1"
  ) {
    // For signal/data, the Origin class is determined by the ticket binding.
    // Before the ticket is presented, we accept either class provisionally;
    // the ticket's bound class is enforced during admission.
    return ticketOriginClass ?? "browser_same_origin";
  }
  throw new OriginVerificationError("origin_mismatch");
}
