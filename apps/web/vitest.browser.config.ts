import { resolve } from "node:path";
import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": resolve(__dirname, "./src"),
    },
  },
  test: {
    include: ["src/**/*.browser.test.{ts,tsx}"],
    passWithNoTests: false,
    server: {
      deps: {
        inline: [/react/, /react-dom/, /react\//, /react-dom\//],
      },
    },
    browser: {
      enabled: true,
      provider: playwright(),
      instances: [{ browser: "chromium", headless: true }],
    },
  },
});
