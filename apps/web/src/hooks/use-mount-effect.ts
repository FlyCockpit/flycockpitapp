import { type EffectCallback, useEffect } from "react";

/**
 * Runs a callback once on mount. This is the approved escape hatch
 * for one-time external sync (useEffect with empty deps).
 */
export function useMountEffect(fn: EffectCallback) {
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(fn, []);
}
