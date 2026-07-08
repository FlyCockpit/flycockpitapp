import { useThemeColorMeta } from "@/hooks/use-theme-color-meta";

/**
 * Headless component that keeps `<meta name="theme-color">` matched to the
 * resolved app theme (see useThemeColorMeta). Must render inside
 * `<ThemeProvider>` so next-themes' `useTheme()` resolves. Renders nothing.
 */
export function ThemeColorSync() {
  useThemeColorMeta();
  return null;
}
