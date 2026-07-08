/**
 * Anti-FOUC theme bootstrap. Inlined into the document `<head>` so it runs
 * before first paint — setting the `.dark` class and `color-scheme` from the
 * persisted/system preference so the canvas never flashes the wrong theme —
 * with NO extra network request on the critical render path.
 *
 * Single source of truth shared by two consumers that MUST agree:
 *   - apps/web/src/routes/__root.tsx inlines this via `dangerouslySetInnerHTML`
 *     as the first child of `<head>` (must stay first; must NOT be async/defer).
 *   - apps/server/src/index.ts hashes this string at startup and adds the
 *     resulting `'sha256-…'` to the `script-src` CSP directive, so the inline
 *     script is allowed under `script-src 'self' 'nonce-…'` (an inline script
 *     needs a nonce or a hash; a static bootstrap uses a hash).
 *
 * Because the CSP hash is derived from THIS string at runtime, the two can
 * never drift: edit the script and the allowed hash updates automatically.
 *
 * Keep `storageKey` ("vite-ui-theme") and the default ("system" — follow the OS
 * `prefers-color-scheme`) in lockstep with `<ThemeProvider>` in __root.tsx.
 *
 * The `backgroundColor` values MUST mirror `--background` for `:root` (light)
 * and `.dark` in packages/ui/src/styles/globals.css. Setting it inline paints
 * the correct canvas on the very FIRST frame — before the render-blocking
 * stylesheet that defines `--background` is applied — so a cold start shows no
 * white flash, and it is theme-aware: a light-mode user never sees a dark flash
 * and vice versa.
 */
export const THEME_INIT_SCRIPT = `(() => {
  try {
    const k = "vite-ui-theme";
    const t = localStorage.getItem(k);
    const sysDark = matchMedia("(prefers-color-scheme: dark)").matches;
    // Stored: resolve "dark" or "system"+OS. No stored value: default is
    // "system", so follow the OS preference (matches defaultTheme="system").
    const dark = t ? t === "dark" || (t === "system" && sysDark) : sysDark;
    const el = document.documentElement;
    if (dark) el.classList.add("dark");
    else el.classList.remove("dark");
    el.style.colorScheme = dark ? "dark" : "light";
    el.style.backgroundColor = dark ? "oklch(0.148 0.004 228.8)" : "oklch(1 0 0)";
    // Tint the iOS standalone-PWA status bar (and Android toolbar) to the
    // RESOLVED app theme rather than the OS prefers-color-scheme. iOS colors the
    // status-bar strip from <meta name="theme-color">; keying it to the OS (the
    // old static media metas) made a dark-mode app show a white strip whenever
    // the phone itself was in light mode. We create the meta HERE (this script
    // is the first child of <head>, before HeadContent), so the first frame is
    // correct; useThemeColorMeta keeps it in sync on later in-app toggles.
    var m = document.querySelector('meta[name="theme-color"]');
    if (!m) {
      m = document.createElement("meta");
      m.setAttribute("name", "theme-color");
      document.head.appendChild(m);
    }
    m.setAttribute("content", dark ? "#0c0c0c" : "#ffffff");
  } catch {}
})();`;
