/**
 * theme:apply — change the app's color theme (and font) at will from a shadcn preset.
 *
 * Runs `shadcn apply --only theme,font` and NOTHING ELSE. It never does a full
 * apply: a full apply regenerates every UI component, dropping this template's
 * customizations (the `touch`/`icon-touch` 44px sizes, `overscroll-contain` on
 * overlays, haptics) and breaking the build. Run the full verification loop after theme changes.
 *
 * Because a color/font swap must not change component *config*, the script
 * snapshots both components.json files and restores them verbatim afterward —
 * undoing the only thing `--only theme,font` stomps (style/baseColor/menu).
 *
 * Usage:  pnpm theme:apply <preset-code>
 *   e.g.  pnpm theme:apply b2CPjyJD0
 *
 * Get a preset code from the shadcn theme editor's "Copy Preset" button
 * (https://ui.shadcn.com/create). `shadcn preset decode <code>` shows what it
 * contains. NOTE: the editor's `style`, `iconLibrary`, and any heading font are
 * NOT applied here — those are a one-time "re-skin", not an at-will theme swap
 * .
 */

import { execFileSync, execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname!, "..");
const uiPackageJson = JSON.parse(
  readFileSync(resolve(ROOT, "packages/ui/package.json"), "utf-8"),
) as {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};
const shadcnVersion =
  uiPackageJson.dependencies?.shadcn?.replace(/^[~^]/, "") ??
  uiPackageJson.devDependencies?.shadcn?.replace(/^[~^]/, "");

if (!shadcnVersion) {
  console.error("Refusing: packages/ui/package.json must pin the shadcn CLI version.");
  process.exit(1);
}

const preset = process.argv[2];

if (!preset || preset.startsWith("-")) {
  console.error(
    "Usage: pnpm theme:apply <preset-code>\n" +
      'Get a code from the shadcn theme editor → "Copy Preset" (e.g. b2CPjyJD0).',
  );
  process.exit(1);
}

// Preset codes are base62. Reject anything else before handing it to the CLI.
if (!/^[A-Za-z0-9]+$/.test(preset)) {
  console.error(`Refusing: "${preset}" does not look like a shadcn preset code.`);
  process.exit(1);
}

const COMPONENTS_JSON = ["apps/web/components.json", "packages/ui/components.json"];

// 1. Snapshot components.json — a theme/font swap must not change component config.
const snapshots = COMPONENTS_JSON.map((p) => {
  const path = resolve(ROOT, p);
  return { path, content: readFileSync(path, "utf-8") };
});
const restoreComponentsJson = () => {
  for (const s of snapshots) writeFileSync(s.path, s.content);
};

// 2. Apply ONLY the theme + font parts. Never style/components.
console.log(`\n▶ Applying shadcn preset ${preset} (theme + font only)…`);
try {
  execFileSync(
    "pnpm",
    [
      "dlx",
      `shadcn@${shadcnVersion}`,
      "apply",
      "--preset",
      preset,
      "--only",
      "theme,font",
      "-c",
      "apps/web",
      "-y",
    ],
    { cwd: ROOT, stdio: "inherit" },
  );
} catch {
  restoreComponentsJson();
  console.error("\n✗ shadcn apply failed. components.json restored; nothing else changed.");
  process.exit(1);
}

// 3. Restore components.json verbatim (undo the CLI's style/baseColor/menu rewrite).
restoreComponentsJson();
console.log("✓ Restored components.json (kept the base-lyra variant).");

// 4. The font dep + lockfile changes are wanted — keep them, just reconcile install.
console.log("▶ Syncing dependencies…");
execSync("pnpm install", { cwd: ROOT, stdio: "inherit" });

// 5. Safety gate: the theme/font path must never break the build.
console.log("▶ Type-checking…");
let green = true;
try {
  execSync("pnpm check-types", { cwd: ROOT, stdio: "inherit" });
} catch {
  green = false;
}

// 6. Report + the follow-ups the script deliberately does not automate.
const rule = "─".repeat(64);
console.log(`\n${rule}`);
if (green) {
  console.log("✓ Theme applied and type-check passed.");
} else {
  console.log("✗ Type-check FAILED — unexpected for --only theme,font.");
  console.log("  If you see button size-variant errors, a FULL apply ran somewhere.");
  console.log("  Inspect with: git diff");
}
console.log("\nFollow-ups this script does not automate (do these by hand or with an agent):");
console.log("  1. Regenerate the --primary-* / --grey-* ramps in");
console.log("     packages/ui/src/styles/globals.css so their hue matches the new --primary.");
console.log("  2. Update the PWA theme_color/background_color hex in apps/web/vite.config.ts");
console.log("     and the theme-color <meta> in apps/web/src/routes/__root.tsx.");
console.log("  3. If a font was added, it's pinned in packages/ui/package.json and the old");
console.log("     font's @import may remain in globals.css. Move the dep to the pnpm catalog");
console.log(
  "     (pnpm-workspace.yaml, like @fontsource-variable/roboto) and drop the unused @import.",
);
console.log(`\nReview the change:  git diff -- packages/ui/src/styles/globals.css`);

process.exit(green ? 0 : 1);
