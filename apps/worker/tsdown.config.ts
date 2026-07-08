import { defineConfig } from "tsdown";

export default defineConfig({
  entry: "./src/index.ts",
  format: "esm",
  outDir: "./dist",
  clean: true,
  // Bundle the workspace (@flycockpit/*) packages into the output. The runtime
  // image (Dockerfile.worker) ships only this app's dist + node_modules — it
  // does NOT copy packages/*/dist — so anything left external would resolve to
  // a dangling node_modules symlink and crash at boot with ERR_MODULE_NOT_FOUND
  // (e.g. "Cannot find package '@flycockpit/env'"). Mirrors apps/server.
  deps: {
    alwaysBundle: [/@flycockpit\/.*/],
    // sharp is a native module pulled in transitively via @flycockpit/api's image
    // helpers (analyze-asset handler → @flycockpit/api/lib/assets). Bundling its JS
    // detaches it from its platform binary (@img/sharp-linux-x64) and crashes at
    // runtime. Keep it external so it resolves from node_modules — this requires
    // sharp to be a direct dependency of this package (see package.json), so pnpm
    // places it where the bundled output can resolve it. Same rule as apps/server.
    neverBundle: ["sharp"],
  },
});
