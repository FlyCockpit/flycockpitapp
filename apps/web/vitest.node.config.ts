import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    exclude: ["**/*.browser.test.{ts,tsx}"],
    passWithNoTests: false,
  },
});
