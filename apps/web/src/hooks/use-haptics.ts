import { useWebHaptics } from "web-haptics/react";

/**
 * Haptic feedback hook for native-like touch interactions.
 *
 * Usage:
 *   const { trigger } = useHaptics();
 *   <button onClick={() => { trigger("light"); doAction(); }}>
 *
 * Presets: "success" | "warning" | "error" | "light" | "medium" | "heavy" | "selection"
 */
export function useHaptics() {
  return useWebHaptics();
}
