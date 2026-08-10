import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: process.env.TEST_REDIS_URL
      ? configDefaults.exclude
      : [...configDefaults.exclude, "**/*.redis.test.ts"],
  },
});
