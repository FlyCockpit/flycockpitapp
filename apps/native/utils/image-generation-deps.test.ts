import { describe, expect, it } from "vitest";
import {
  FORBIDDEN_DUPLICATE_LIBRARIES,
  FORBIDDEN_FILESYSTEM_LIBRARIES,
  FORBIDDEN_PICKER_LIBRARIES,
  FORBIDDEN_SHARE_LIBRARIES,
  IMAGE_GENERATION_EXPO_PACKAGES,
  isForbiddenDuplicateLibrary,
  isImageGenerationExpoPackage,
  NATIVE_BASELINE_PACKAGES,
  validateImageGenerationDeps,
} from "./image-generation-deps";

const exactCatalog = IMAGE_GENERATION_EXPO_PACKAGES;

function baselineDeps(): Record<string, string> {
  const map: Record<string, string> = {};
  for (const pkg of NATIVE_BASELINE_PACKAGES) map[pkg] = "catalog:";
  for (const pkg of exactCatalog) map[pkg] = "catalog:";
  map.typescript = "catalog:";
  map.vitest = "catalog:";
  map["@types/react"] = "catalog:";
  return map;
}

describe("image generation deps validation", () => {
  it("the exact catalog is the four Expo packages only", () => {
    expect(exactCatalog).toEqual([
      "expo-document-picker",
      "expo-image-picker",
      "expo-file-system",
      "expo-sharing",
    ]);
  });

  it("forbidden duplicate libraries cover picker/filesystem/share", () => {
    expect(FORBIDDEN_PICKER_LIBRARIES).toContain("react-native-document-picker");
    expect(FORBIDDEN_PICKER_LIBRARIES).toContain("react-native-image-picker");
    expect(FORBIDDEN_FILESYSTEM_LIBRARIES).toContain("react-native-fs");
    expect(FORBIDDEN_SHARE_LIBRARIES).toContain("react-native-share");
    expect(FORBIDDEN_DUPLICATE_LIBRARIES).toContain("react-native-document-picker");
  });

  it("validates a baseline native package.json with the exact catalog", () => {
    const result = validateImageGenerationDeps(baselineDeps());
    expect(result.valid).toBe(true);
    expect(result.missing).toEqual([]);
    expect(result.forbidden).toEqual([]);
    expect(result.unexpected).toEqual([]);
  });

  it("reports missing packages when the catalog is incomplete", () => {
    const deps = baselineDeps();
    delete deps["expo-document-picker"];
    delete deps["expo-file-system"];
    const result = validateImageGenerationDeps(deps);
    expect(result.valid).toBe(false);
    expect(result.missing).toContain("expo-document-picker");
    expect(result.missing).toContain("expo-file-system");
  });

  it("reports forbidden duplicate libraries", () => {
    const deps = baselineDeps();
    deps["react-native-document-picker"] = "^3.0.0";
    deps["react-native-fs"] = "^2.0.0";
    deps["react-native-share"] = "^9.0.0";
    const result = validateImageGenerationDeps(deps);
    expect(result.valid).toBe(false);
    expect(result.forbidden).toContain("react-native-document-picker");
    expect(result.forbidden).toContain("react-native-fs");
    expect(result.forbidden).toContain("react-native-share");
  });

  it("reports unexpected packages not in the exact catalog or baseline", () => {
    const deps = baselineDeps();
    deps["some-random-library"] = "^1.0.0";
    const result = validateImageGenerationDeps(deps);
    expect(result.valid).toBe(false);
    expect(result.unexpected).toContain("some-random-library");
  });

  it("isImageGenerationExpoPackage and isForbiddenDuplicateLibrary", () => {
    expect(isImageGenerationExpoPackage("expo-document-picker")).toBe(true);
    expect(isImageGenerationExpoPackage("react-native-document-picker")).toBe(false);
    expect(isForbiddenDuplicateLibrary("react-native-document-picker")).toBe(true);
    expect(isForbiddenDuplicateLibrary("expo-document-picker")).toBe(false);
  });
});
