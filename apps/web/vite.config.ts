import { execSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

import tailwindcss from "@tailwindcss/vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";
import { VitePWA } from "vite-plugin-pwa";

function getBuildVersion(): string {
  // process.env is correct here — Vite config runs at build time outside the app runtime.
  if (process.env.BUILD_VERSION) return process.env.BUILD_VERSION;
  if (process.env.RENDER_GIT_COMMIT) return process.env.RENDER_GIT_COMMIT;
  try {
    return execSync("git rev-parse --short HEAD", {
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
  } catch {
    // Fallback when git is unavailable (e.g. inside the Docker builder image).
    // Must be unique per build so `useAppUpdate` can still detect new deploys.
    return `build-${randomUUID()}`;
  }
}

// Exposed to the app as `__APP_VERSION__` (define below). Update detection is
// driven by the service-worker lifecycle (vite-plugin-pwa autoUpdate), NOT by
// comparing this string against a fetched version.json — the old version.json
// build plugin and the `useAppUpdate` poll that read it were removed (they
// caused the false "new version available" toast). Kept here as a build
// identifier; pass BUILD_VERSION (the git SHA) in CI/Docker to make it
// deterministic.
const buildVersion = getBuildVersion();

function parseDevPort(value: string | undefined, fallback: number, label: string): number {
  if (!value) return fallback;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`${label} must be an integer TCP port between 1 and 65535.`);
  }
  return port;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function getPortlessApiTarget(): string {
  try {
    const raw = readFileSync(path.resolve(__dirname, "../../portless.json"), "utf-8");
    const config: unknown = JSON.parse(raw);
    if (!isRecord(config) || !isRecord(config.apps)) return "https://api.flycockpit.localhost";
    const server = config.apps["apps/server"];
    if (!isRecord(server) || typeof server.name !== "string" || server.name.length === 0) {
      return "https://api.flycockpit.localhost";
    }
    return `https://${server.name}.localhost`;
  } catch {
    return "https://api.flycockpit.localhost";
  }
}

function normalizeProxyTarget(value: string | undefined): { http: string; ws: string } {
  const target =
    value || (process.env.PORTLESS_URL ? getPortlessApiTarget() : "http://localhost:3000");
  const url = new URL(target);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("VITE_DEV_SERVER_URL must start with http:// or https://.");
  }
  url.pathname = "";
  url.search = "";
  url.hash = "";
  const wsUrl = new URL(url);
  wsUrl.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return { http: url.toString().replace(/\/$/, ""), ws: wsUrl.toString().replace(/\/$/, "") };
}

export default defineConfig(({ mode }) => {
  // Keep build-time and runtime branding in lockstep by loading the same
  // app-local env files (`apps/web/.env*`) that the client runtime uses.
  const envDir = __dirname;
  const env = loadEnv(mode, envDir, "VITE_");
  const appName = env.VITE_APP_NAME || "App";
  const devPort = parseDevPort(
    process.env.VITE_DEV_PORT ?? env.VITE_DEV_PORT ?? process.env.PORT,
    3001,
    "VITE_DEV_PORT",
  );
  const devProxyTarget = normalizeProxyTarget(
    process.env.VITE_DEV_SERVER_URL ?? env.VITE_DEV_SERVER_URL,
  );

  return {
    envDir,
    plugins: [
      tailwindcss(),
      tanstackStart(),
      react(),
      VitePWA({
        strategies: "injectManifest",
        srcDir: "src",
        filename: "sw.ts",
        registerType: "autoUpdate",
        manifest: {
          name: appName,
          short_name: appName,
          description: `${appName} - PWA Application`,
          theme_color: "#0c0c0c",
          background_color: "#0c0c0c",
        },
        pwaAssets: { disabled: false, config: true },
        devOptions: { enabled: true, type: "module" },
        injectManifest: {
          globPatterns: ["**/*.{js,css,html,ico,png,svg,woff2}"],
          maximumFileSizeToCacheInBytes: 5 * 1024 * 1024,
        },
      }),
    ],
    define: {
      __APP_VERSION__: JSON.stringify(buildVersion),
    },
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },
    build: {
      rolldownOptions: {
        output: {
          manualChunks(id) {
            // Anchor on `/node_modules/<pkg>/` so this matches ONLY the React
            // runtime — NOT every package whose path happens to contain the
            // substring "react" (e.g. `@vidstack/react`, `react-markdown`,
            // `react-i18next`). A loose `/react/` test here pulls those heavy,
            // route-specific deps into the eager base chunk and defeats the
            // per-route code-splitting TanStack Start already does. Keep this
            // list to the libraries every page genuinely needs at first paint.
            if (
              id.includes("/node_modules/react/") ||
              id.includes("/node_modules/react-dom/") ||
              id.includes("/node_modules/scheduler/") ||
              id.includes("/node_modules/react-is/")
            ) {
              return "react-vendor";
            }
            if (
              id.includes("/node_modules/@tanstack/react-router/") ||
              id.includes("/node_modules/@tanstack/react-query/") ||
              id.includes("/node_modules/@tanstack/react-form/")
            ) {
              return "tanstack";
            }
            // `sileo` (Toaster) and `next-themes` (ThemeProvider) render in the
            // root, so they're genuinely needed at first paint — keep them in the
            // eager `ui` chunk. `lucide-react` is NOT listed here on purpose: a
            // named chunk would collapse every icon used anywhere in the app
            // (admin, dashboard, settings…) into one eager chunk, so first paint
            // pays for icons it never renders. Left unlisted, Rollup splits icons
            // into their owning route chunks and hoists shared ones automatically.
            if (id.includes("/node_modules/sileo/") || id.includes("/node_modules/next-themes/")) {
              return "ui";
            }
            if (
              id.includes("/node_modules/@orpc/client/") ||
              id.includes("/node_modules/@orpc/server/") ||
              id.includes("/node_modules/@orpc/tanstack-query/")
            ) {
              return "orpc";
            }
            if (id.includes("/node_modules/better-auth/")) {
              return "auth";
            }
            if (id.includes("/node_modules/zod/")) {
              return "zod";
            }
          },
        },
      },
    },
    server: {
      port: devPort,
      // Opt in to 0.0.0.0 when running inside the agent docker-compose stack
      // (docker-compose.agent.yml sets VITE_DEV_HOST=true). Unset on the host
      // so `pnpm dev` keeps its localhost-only default.
      host: process.env.VITE_DEV_HOST === "true" ? true : undefined,
      proxy: {
        "/api": { target: devProxyTarget.http, changeOrigin: true, secure: false },
        "/rpc": { target: devProxyTarget.http, changeOrigin: true, secure: false },
        // Admin MCP endpoint (apps/server/src/mcp). Without this proxy entry
        // the SPA dev server intercepts /mcp and returns the index.html
        // instead of routing to the Hono server.
        "/mcp": { target: devProxyTarget.http, changeOrigin: true, secure: false },
        // Dedicated service-worker renewal endpoint (see
        // `apps/server/src/index.ts → POST /sw/push-renew`). In dev the SW runs
        // on the Vite origin; proxy so the relative fallback still reaches the
        // API server.
        "/sw": { target: devProxyTarget.http, changeOrigin: true, secure: false },
        "/ws": { target: devProxyTarget.ws, ws: true, changeOrigin: true, secure: false },
      },
    },
  };
});
