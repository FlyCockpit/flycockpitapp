import { registerSW } from "virtual:pwa-register";

import { useMountEffect } from "@/hooks/use-mount-effect";

/**
 * Registers the service worker for silent, no-prompt PWA updates.
 *
 * Update model: SILENT AUTO-UPDATE, NO FORCED RELOAD.
 *
 * The PWA plugin runs with `registerType: "autoUpdate"` (apps/web/vite.config.ts).
 * Workbox precaches each new build; the SW's `skipWaiting()` + `clients.claim()`
 * (apps/web/src/sw.ts) make it the active SW, and the new assets are picked up on
 * the next natural app launch / navigation. There is intentionally NO "new
 * version available" toast and NO `window.location.reload()` — those produced the
 * false-update banner and surprise reloads.
 *
 * This hook's only remaining job is to ensure the SW is actually REGISTERED.
 * This app has no static index.html, so vite-plugin-pwa's auto-injected
 * `registerSW.js` <script> tag is never emitted — registration must be wired
 * explicitly. `registerSW({ immediate: true })`
 * registers on mount and is idempotent across re-renders.
 */
export function useAppUpdate() {
  useMountEffect(() => {
    // Defer registration off the initial hydration window: SW registration kicks
    // off Workbox precache fetches that otherwise contend with first paint / TBT.
    // We still register EXPLICITLY with `immediate: true` (this app has no static
    // index.html, so vite-plugin-pwa's auto-injected registerSW.js never runs, and
    // `immediate: false` would wait for a `load` event that may have already fired
    // by the time this mount effect runs — leaving the SW unregistered). Idle is
    // the safe middle: guaranteed to run (3s timeout), just not during hydration.
    const register = () => registerSW({ immediate: true });
    if (typeof window.requestIdleCallback === "function") {
      const id = window.requestIdleCallback(register, { timeout: 3000 });
      return () => window.cancelIdleCallback?.(id);
    }
    const id = window.setTimeout(register, 1000);
    return () => window.clearTimeout(id);
  });
}
