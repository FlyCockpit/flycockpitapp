import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname!, "..");
const nativeRoot = resolve(ROOT, "apps/native");
const nativeEnvPath = resolve(nativeRoot, ".env");
const nativeEnvExamplePath = resolve(nativeRoot, ".env.example");
const generatedNativeDirs = ["ios", "android"].map((dir) => resolve(nativeRoot, dir));

function log(message: string) {
  console.log(`[native-doctor] ${message}`);
}

function fail(message: string): never {
  console.error(`[native-doctor] ERROR: ${message}`);
  process.exit(1);
}

function readEnvValue(contents: string, key: string): string | null {
  for (const raw of contents.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(new RegExp(`^${key}\\s*=\\s*(.*)$`));
    if (!match) continue;
    return (match[1] ?? "").trim().replace(/^["']|["']$/g, "") || null;
  }
  return null;
}

for (const generatedDir of generatedNativeDirs) {
  if (existsSync(generatedDir)) {
    fail(
      `${generatedDir.replace(`${ROOT}/`, "")} exists. This template is managed Expo by default; ` +
        "do not run `expo prebuild` or commit generated native projects unless the app is intentionally moving to a bare/prebuild workflow.",
    );
  }
}

if (!existsSync(nativeEnvExamplePath)) {
  fail("apps/native/.env.example is missing.");
}

if (!existsSync(nativeEnvPath)) {
  fail("apps/native/.env is missing. Run `cp apps/native/.env.example apps/native/.env`.");
}

const nativeEnv = readFileSync(nativeEnvPath, "utf-8");
const serverUrl = readEnvValue(nativeEnv, "EXPO_PUBLIC_SERVER_URL");

if (!serverUrl) {
  fail("EXPO_PUBLIC_SERVER_URL is missing in apps/native/.env.");
}

try {
  const parsed = new URL(serverUrl);
  if (!["http:", "https:"].includes(parsed.protocol)) {
    fail("EXPO_PUBLIC_SERVER_URL must use http or https.");
  }
  if (parsed.hostname === "0.0.0.0") {
    fail(
      "EXPO_PUBLIC_SERVER_URL cannot use 0.0.0.0; use localhost, 10.0.2.2, a LAN IP, or a tunnel.",
    );
  }
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
    fail("EXPO_PUBLIC_SERVER_URL must be an origin only, with no path, query, or hash.");
  }
  log(`EXPO_PUBLIC_SERVER_URL=${parsed.origin}`);
} catch {
  fail("EXPO_PUBLIC_SERVER_URL must be a valid absolute URL.");
}

log("native checks passed");
