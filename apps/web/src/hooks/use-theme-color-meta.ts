import { useTheme } from "next-themes";
import { useEffect } from "react";

// Mirror `--background` for `.dark` / `:root` in packages/ui/src/styles/globals.css.
// Kept in lockstep with the values in THEME_INIT_SCRIPT (packages/config/src/theme-init.ts).
const THEME_COLORS = { dark: "#0c0c0c", light: "#ffffff" } as const;

/**
 * Keeps `<meta name="theme-color">` in sync with the RESOLVED app theme so the
 * iOS standalone-PWA status bar (and Android toolbar) matches the UI even when
 * the user's chosen theme differs from their OS appearance. The anti-FOUC
 * THEME_INIT_SCRIPT seeds this meta on the first frame; this hook updates it
 * whenever the user toggles the theme (or the system preference changes while
 * `theme === "system"`). Must be called from inside `<ThemeProvider>`.
 */
export function useThemeColorMeta(): void {
  const { resolvedTheme } = useTheme();

  useEffect(() => {
    if (resolvedTheme !== "dark" && resolvedTheme !== "light") return;
    let meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
    if (!meta) {
      meta = document.createElement("meta");
      meta.name = "theme-color";
      document.head.appendChild(meta);
    }
    meta.content = THEME_COLORS[resolvedTheme];
  }, [resolvedTheme]);
}
