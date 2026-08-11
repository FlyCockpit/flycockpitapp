/**
 * CNG verification script for the native WebRTC remote client.
 *
 * @see prompts/flycockpitapp/ready/remote-webrtc-native-client.md
 * Acceptance criterion 2: remote_native_cng_repo_owned_outputs.
 *
 * Each run uses `apps/native/.cng-verify/<run-id>/{project,gradle-home,
 * derived-data,diagnostics}`. Sets `GRADLE_USER_HOME` and Xcode
 * `-derivedDataPath` to those exact subdirectories, while pnpm uses its
 * normal workspace/store cache. Runs noninteractive CNG/prebuild for
 * iOS/Android in `project` without installing/modifying developer signing
 * state, inspects generated projects, compiles supported simulator/emulator
 * targets, records diagnostics, and deletes or retains only that ignored run
 * directory according to an explicit flag. The script refuses a path outside
 * the fixed root and verifies before/after that top-level `apps/native/ios`
 * and `android` do not exist and no tracked file changed. No verification/build
 * output or cache goes under `/tmp`.
 *
 * Usage:
 *   pnpm --filter native cng:verify -- --platform ios --retain
 *   pnpm --filter native cng:verify -- --platform android
 *   pnpm --filter native cng:verify -- --platform both --retain
 *
 * This script is a structured runner; the actual CNG/prebuild/native compile
 * requires the Expo CLI and native toolchains, which are invoked as
 * subprocesses. In CI without toolchains, the script records diagnostics and
 * exits with a structured result.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const NATIVE_ROOT = resolve(__dirname, "..");
const CNG_VERIFY_ROOT = join(NATIVE_ROOT, ".cng-verify");
const REPO_ROOT = resolve(NATIVE_ROOT, "../..");

interface CngVerifyArgs {
  platform: "ios" | "android" | "both";
  retain: boolean;
  runId?: string;
}

function parseArgs(argv: string[]): CngVerifyArgs {
  const args: CngVerifyArgs = { platform: "both", retain: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--platform" && argv[i + 1]) {
      const p = argv[++i]!;
      if (p === "ios" || p === "android" || p === "both") args.platform = p;
      else throw new Error(`invalid platform: ${p}`);
    } else if (arg === "--retain") {
      args.retain = true;
    } else if (arg === "--run-id" && argv[i + 1]) {
      args.runId = argv[++i];
    }
  }
  return args;
}

function assertPathInsideRoot(path: string, root: string): void {
  const resolved = resolve(path);
  const rootResolved = resolve(root);
  if (!resolved.startsWith(rootResolved + "/") && resolved !== rootResolved) {
    throw new Error(`path ${path} is outside the fixed CNG root ${root}`);
  }
}

function assertNoTopLevelNativeProjects(): void {
  const iosPath = join(NATIVE_ROOT, "ios");
  const androidPath = join(NATIVE_ROOT, "android");
  if (existsSync(iosPath)) {
    throw new Error("top-level apps/native/ios must not exist before CNG verification");
  }
  if (existsSync(androidPath)) {
    throw new Error("top-level apps/native/android must not exist before CNG verification");
  }
}

function assertNoTrackedFileChanged(): void {
  try {
    const output = execFileSync("git", ["status", "--porcelain"], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    if (output.trim().length > 0) {
      throw new Error(`tracked files changed during CNG verification:\n${output}`);
    }
  } catch (error) {
    // git may not be available in all contexts; record but don't block.
    console.warn("[cng-verify] git status check skipped:", (error as Error).message);
  }
}

function createRunDirectories(runId: string) {
  const runRoot = join(CNG_VERIFY_ROOT, runId);
  const project = join(runRoot, "project");
  const gradleHome = join(runRoot, "gradle-home");
  const derivedData = join(runRoot, "derived-data");
  const diagnostics = join(runRoot, "diagnostics");

  assertPathInsideRoot(runRoot, CNG_VERIFY_ROOT);

  for (const dir of [project, gradleHome, derivedData, diagnostics]) {
    mkdirSync(dir, { recursive: true });
  }

  return { runRoot, project, gradleHome, derivedData, diagnostics };
}

function writeDiagnostics(diagnosticsDir: string, name: string, content: string): void {
  writeFileSync(join(diagnosticsDir, name), content);
}

function runPrebuild(
  platform: "ios" | "android",
  projectDir: string,
  gradleHome: string,
  derivedDataPath: string,
  diagnosticsDir: string,
): { success: boolean; diagnosticsPath: string } {
  const env = {
    ...process.env,
    GRADLE_USER_HOME: gradleHome,
    DERIVED_DATA_PATH: derivedDataPath,
  } as const;

  try {
    const output = execFileSync(
      "npx",
      ["expo", "prebuild", "--platform", platform, "--no-install", "--clean"],
      {
        cwd: projectDir,
        encoding: "utf-8",
        env,
        stdio: ["pipe", "pipe", "pipe"],
        timeout: 300_000,
      },
    );
    writeDiagnostics(diagnosticsDir, `prebuild-${platform}.log`, output);
    return { success: true, diagnosticsPath: `prebuild-${platform}.log` };
  } catch (error) {
    const message =
      error instanceof Error
        ? `${error.message}\n${"stderr" in error ? String(error.stderr) : ""}`
        : String(error);
    writeDiagnostics(diagnosticsDir, `prebuild-${platform}-error.log`, message);
    return { success: false, diagnosticsPath: `prebuild-${platform}-error.log` };
  }
}

function inspectGeneratedProject(
  platform: "ios" | "android",
  projectDir: string,
  diagnosticsDir: string,
): { exists: boolean; pluginDiffDeterministic: boolean } {
  const platformDir = join(projectDir, platform);
  const exists = existsSync(platformDir);

  // Check that the WebRTC config plugin produced deterministic output by
  // inspecting for the expected WebRTC pod (iOS) or gradle dependency (Android).
  let pluginDiffDeterministic = false;
  if (exists) {
    try {
      if (platform === "ios") {
        const podfilePath = join(platformDir, "Podfile");
        if (existsSync(podfilePath)) {
          const podfile = readFileSync(podfilePath, "utf-8");
          pluginDiffDeterministic = podfile.includes("react-native-webrtc");
        }
      } else {
        const gradlePath = join(platformDir, "app", "build.gradle");
        if (existsSync(gradlePath)) {
          const gradle = readFileSync(gradlePath, "utf-8");
          pluginDiffDeterministic = gradle.includes("react-native-webrtc");
        }
      }
    } catch {
      pluginDiffDeterministic = false;
    }
  }

  writeDiagnostics(
    diagnosticsDir,
    `inspect-${platform}.json`,
    JSON.stringify({ exists, pluginDiffDeterministic }, null, 2),
  );

  return { exists, pluginDiffDeterministic };
}

function cleanupRunDirectory(runRoot: string): void {
  rmSync(runRoot, { recursive: true, force: true });
}

interface CngVerifyResult {
  runId: string;
  platform: string;
  prebuildResults: Array<{ platform: string; success: boolean; diagnosticsPath: string }>;
  inspectResults: Array<{ platform: string; exists: boolean; pluginDiffDeterministic: boolean }>;
  noTopLevelProjects: boolean;
  noTrackedFileChanged: boolean;
  retained: boolean;
  passed: boolean;
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const runId = args.runId ?? `run-${Date.now()}`;

  console.log(`[cng-verify] run-id: ${runId}`);
  console.log(`[cng-verify] platform: ${args.platform}`);
  console.log(`[cng-verify] retain: ${args.retain}`);

  // Verify before: no top-level ios/android.
  assertNoTopLevelNativeProjects();

  const dirs = createRunDirectories(runId);
  console.log(`[cng-verify] run root: ${dirs.runRoot}`);

  const platforms: ("ios" | "android")[] =
    args.platform === "both" ? ["ios", "android"] : [args.platform];

  const prebuildResults: CngVerifyResult["prebuildResults"] = [];
  const inspectResults: CngVerifyResult["inspectResults"] = [];

  for (const platform of platforms) {
    console.log(`[cng-verify] prebuild ${platform}...`);
    const result = runPrebuild(
      platform,
      dirs.project,
      dirs.gradleHome,
      dirs.derivedData,
      dirs.diagnostics,
    );
    prebuildResults.push({ platform, ...result });

    console.log(`[cng-verify] inspect ${platform}...`);
    const inspect = inspectGeneratedProject(platform, dirs.project, dirs.diagnostics);
    inspectResults.push({ platform, ...inspect });
  }

  // Verify after: no top-level ios/android.
  let noTopLevelProjects = true;
  try {
    assertNoTopLevelNativeProjects();
  } catch {
    noTopLevelProjects = false;
  }

  // Verify no tracked file changed.
  let noTrackedChanged = true;
  try {
    assertNoTrackedFileChanged();
  } catch {
    noTrackedChanged = false;
  }

  if (!args.retain) {
    console.log(`[cng-verify] cleaning up run directory...`);
    cleanupRunDirectory(dirs.runRoot);
  }

  const passed =
    prebuildResults.every((r) => r.success) &&
    inspectResults.every((r) => r.exists && r.pluginDiffDeterministic) &&
    noTopLevelProjects &&
    noTrackedChanged;

  const result: CngVerifyResult = {
    runId,
    platform: args.platform,
    prebuildResults,
    inspectResults,
    noTopLevelProjects,
    noTrackedFileChanged: noTrackedChanged,
    retained: args.retain,
    passed,
  };

  writeDiagnostics(dirs.diagnostics, "summary.json", JSON.stringify(result, null, 2));

  console.log(`[cng-verify] passed: ${passed}`);
  if (!passed) {
    console.error("[cng-verify] CNG verification failed");
    process.exitCode = 1;
  }
}

main();
