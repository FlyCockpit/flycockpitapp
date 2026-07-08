import { defineConfig } from "tsdown";

export default defineConfig({
  entry: "./src/index.ts",
  format: "esm",
  outDir: "./dist",
  clean: true,
  deps: {
    alwaysBundle: [/@flycockpit\/.*/],
    // sharp is a native module: it loads a platform-specific binary
    // (@img/sharp-linux-x64) from node_modules at runtime. Bundling its JS
    // detaches it from that binary and crashes the server on boot ("Could not
    // load the sharp module using the linux-x64 runtime"). Keep it external so
    // it resolves from node_modules at runtime — this requires sharp to be a
    // direct dependency of this package (see package.json). (The TanStack Start
    // SSR handler at apps/web/dist/server is imported via a runtime-computed
    // specifier in src/index.ts, so rolldown leaves it external automatically —
    // no entry needed here.)
    neverBundle: ["sharp"],
  },
});
