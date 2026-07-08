import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: false,
    environment: "node",
    passWithNoTests: true,
    exclude: [...configDefaults.exclude, "**/dist/**", "**/dev-dist/**"],
  },
});
