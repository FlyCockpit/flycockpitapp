import { createEnv } from "@t3-oss/env-core";
import { z } from "zod";
import { originUrl } from "./url.js";

// Narrow type-only shim for `window.location.origin` so this file compiles
// without pulling DOM into the package's `lib`. The runtime guard
// (`typeof window !== "undefined"`) still works on Node (where this module
// happens to be imported during SSR-style flows) and the browser.
declare const window: { location: { origin: string } } | undefined;

const baseEnv = createEnv({
  clientPrefix: "VITE_",
  client: {
    VITE_APP_NAME: z.string().min(1).max(80).optional(),
    VITE_SERVER_URL: originUrl("VITE_SERVER_URL").optional(),
    VITE_DEV_PORT: z.coerce.number().int().min(1).max(65_535).optional(),
    VITE_DEV_SERVER_URL: originUrl("VITE_DEV_SERVER_URL").optional(),
    VITE_VAPID_PUBLIC_KEY: z.string().optional(),
  },
  runtimeEnv: (import.meta as unknown as Record<string, unknown>).env as Record<
    string,
    string | undefined
  >,
  emptyStringAsUndefined: true,
});

export const env = {
  ...baseEnv,
  get VITE_APP_NAME() {
    return baseEnv.VITE_APP_NAME ?? "App";
  },
  get VITE_SERVER_URL() {
    return (
      baseEnv.VITE_SERVER_URL ??
      (typeof window !== "undefined" ? window.location.origin : "http://localhost:3000")
    );
  },
};
