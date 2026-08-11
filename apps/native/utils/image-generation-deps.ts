/**
 * Image-generation native Expo dependency catalog validation.
 *
 * Acceptance criterion 1: only the four exact Expo packages are used for this
 * feature, aligned to the current SDK through Expo install policy, with no
 * duplicate picker/filesystem/share library.
 *
 * The exact package catalog for this feature is:
 * - `expo-document-picker` (document/file picker)
 * - `expo-image-picker` (image-library/camera selection, already present)
 * - `expo-file-system` (app-sandbox temporary/download files)
 * - `expo-sharing` (share sheet)
 *
 * No package beyond this exact catalog may be added unless separately
 * approved. Versions must match the repository's installed Expo SDK; the
 * repository's `expo install` command resolves that catalog.
 */

/** The exact four Expo packages authorized for the image-generation native feature. */
export const IMAGE_GENERATION_EXPO_PACKAGES: readonly string[] = [
  "expo-document-picker",
  "expo-image-picker",
  "expo-file-system",
  "expo-sharing",
];

/** Picker libraries forbidden because they duplicate the exact catalog. */
export const FORBIDDEN_PICKER_LIBRARIES: readonly string[] = [
  "react-native-document-picker",
  "expo-document-picker-types",
  "react-native-image-picker",
  "react-native-image-crop-picker",
  "expo-image-picker-types",
];

/** Filesystem libraries forbidden because they duplicate the exact catalog. */
export const FORBIDDEN_FILESYSTEM_LIBRARIES: readonly string[] = [
  "react-native-fs",
  "expo-file-system-next",
  "react-native-blob-util",
  "react-native-fetch-blob",
];

/** Share libraries forbidden because they duplicate the exact catalog. */
export const FORBIDDEN_SHARE_LIBRARIES: readonly string[] = [
  "react-native-share",
  "expo-sharing-types",
];

/** All forbidden duplicate libraries for this feature. */
export const FORBIDDEN_DUPLICATE_LIBRARIES: readonly string[] = [
  ...FORBIDDEN_PICKER_LIBRARIES,
  ...FORBIDDEN_FILESYSTEM_LIBRARIES,
  ...FORBIDDEN_SHARE_LIBRARIES,
];

/** A parsed package.json dependency map. */
export type DependencyMap = Readonly<Record<string, string>>;

/** The result of validating a native package.json for the image-generation feature. */
export interface ImageGenerationDepsValidation {
  valid: boolean;
  /** Missing packages from the exact catalog. */
  missing: string[];
  /** Forbidden duplicate libraries found. */
  forbidden: string[];
  /** Packages present that are not in the exact catalog and not otherwise allowed. */
  unexpected: string[];
}

/** The allowed baseline native packages (present before this feature). */
export const NATIVE_BASELINE_PACKAGES: readonly string[] = [
  "@better-auth/expo",
  "@expo/metro-runtime",
  "@expo/vector-icons",
  "@gorhom/bottom-sheet",
  "@orpc/client",
  "@orpc/tanstack-query",
  "@flycockpit/api",
  "@flycockpit/auth",
  "@flycockpit/cockpit-protocol",
  "@flycockpit/env",
  "@tanstack/react-form",
  "@tanstack/react-query",
  "better-auth",
  "expo",
  "expo-clipboard",
  "expo-constants",
  "expo-font",
  "expo-haptics",
  "expo-image-picker",
  "expo-linking",
  "expo-network",
  "expo-notifications",
  "expo-router",
  "expo-secure-store",
  "expo-status-bar",
  "expo-web-browser",
  "heroui-native",
  "react",
  "react-dom",
  "react-native",
  "react-native-gesture-handler",
  "react-native-keyboard-controller",
  "react-native-reanimated",
  "react-native-safe-area-context",
  "react-native-screens",
  "react-native-svg",
  "react-native-web",
  "react-native-worklets",
  "tailwind-merge",
  "tailwind-variants",
  "tailwindcss",
  "uniwind",
  "zod",
];

/**
 * Validate a native app's dependencies for the image-generation feature.
 *
 * Proves only the four exact Expo packages are used, with no duplicate
 * picker/filesystem/share library. `expo-image-picker` is already present in
 * the baseline; the three new packages must be added.
 */
export function validateImageGenerationDeps(
  dependencies: DependencyMap,
  options: { allowBaseline?: boolean } = {},
): ImageGenerationDepsValidation {
  const allowBaseline = options.allowBaseline ?? true;
  const present = new Set(Object.keys(dependencies));
  const missing: string[] = [];
  const forbidden: string[] = [];
  const unexpected: string[] = [];

  for (const pkg of IMAGE_GENERATION_EXPO_PACKAGES) {
    if (!present.has(pkg)) missing.push(pkg);
  }

  for (const pkg of FORBIDDEN_DUPLICATE_LIBRARIES) {
    if (present.has(pkg)) forbidden.push(pkg);
  }

  const allowed = new Set<string>(IMAGE_GENERATION_EXPO_PACKAGES);
  if (allowBaseline) {
    for (const pkg of NATIVE_BASELINE_PACKAGES) allowed.add(pkg);
  }
  // Dev dependencies and @types/* are always allowed.
  for (const pkg of present) {
    if (pkg.startsWith("@types/")) allowed.add(pkg);
    if (pkg === "typescript" || pkg === "vitest") allowed.add(pkg);
  }

  for (const pkg of present) {
    if (!allowed.has(pkg)) unexpected.push(pkg);
  }

  return {
    valid: missing.length === 0 && forbidden.length === 0 && unexpected.length === 0,
    missing: missing.sort(),
    forbidden: forbidden.sort(),
    unexpected: unexpected.sort(),
  };
}

/** Returns `true` if a package name is in the exact image-generation Expo catalog. */
export function isImageGenerationExpoPackage(pkg: string): boolean {
  return IMAGE_GENERATION_EXPO_PACKAGES.includes(pkg);
}

/** Returns `true` if a package name is a forbidden duplicate library. */
export function isForbiddenDuplicateLibrary(pkg: string): boolean {
  return FORBIDDEN_DUPLICATE_LIBRARIES.includes(pkg);
}
