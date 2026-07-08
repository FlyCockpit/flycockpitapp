/**
 * One-shot translation of UI locale bundles via the configured translation
 * provider (default: OpenRouter -> anthropic/claude-haiku-4-5).
 *
 * Reads every `apps/web/src/locales/<source>/*.json`, finds the parallel
 * `apps/web/src/locales/<target>/*.json`, and fills in any leaf string that is
 * missing or empty in the target. Already-populated translations are left
 * untouched (re-runnable / idempotent) unless `--force` is passed.
 *
 * Strategy:
 *   - Bundle one call per namespace: send only the keys that need translating
 *     as a JSON object (contentKind: "json"). The provider's prompt enforces
 *     identical structure + ICU placeholder preservation + Mexican Spanish.
 *   - If the JSON parse fails (or returns an unexpected shape), fall back to
 *     per-key plaintext translation for that namespace.
 *   - Validate placeholders + <Trans> numeric tags survive the round-trip.
 *     In `--strict` mode, retry once and drop the key on failure (i18next
 *     falls back to en-US, which is safer than a broken interpolation).
 *
 * Run:  pnpm i18n:translate                  # fill missing only
 *       pnpm i18n:translate --force          # re-translate everything
 *       pnpm i18n:translate --ns common,auth # subset of namespaces
 *       pnpm i18n:translate --strict         # drop keys that fail validation
 *
 * The script imports `getTranslationProvider` from @flycockpit/i18n-translate so
 * it exercises the same code path as the BullMQ `translate-content` worker.
 * Never logs the API key. The key must be in `process.env.OPENROUTER_API_KEY`
 * (or `ANTHROPIC_API_KEY` if `TRANSLATION_PROVIDER=anthropic`).
 */

import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { parseArgs } from "node:util";

import { getTranslationProvider } from "@flycockpit/i18n-translate";

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

const { values: cli } = parseArgs({
  options: {
    force: { type: "boolean", default: false },
    strict: { type: "boolean", default: false },
    ns: { type: "string" },
    source: { type: "string", default: "en-US" },
    target: { type: "string", default: "es-MX" },
    // Optional explicit dirs override the default `apps/web/src/locales/<locale>`
    // layout so other packages (e.g. `packages/mailer/src/locales/`) can reuse
    // the same script. Both must be provided together if used.
    "source-dir": { type: "string" },
    "target-dir": { type: "string" },
    "exclude-ns": { type: "string" },
    help: { type: "boolean", short: "h", default: false },
  },
  strict: true,
  allowPositionals: false,
});

if (cli.help) {
  console.log(
    [
      "Usage: pnpm i18n:translate [options]",
      "",
      "  --source <locale>       Source locale dir name (default: en-US)",
      "  --target <locale>       Target locale dir name (default: es-MX)",
      "  --source-dir <path>     Absolute path to source locale dir (overrides default web layout)",
      "  --target-dir <path>     Absolute path to target locale dir (overrides default web layout)",
      "  --ns <a,b,c>            Only translate these namespaces (basename without .json)",
      "  --exclude-ns <a,b,c>    Skip these namespaces",
      "  --force                 Overwrite existing non-empty translations",
      "  --strict                Drop keys that fail placeholder validation after retry",
      "  -h, --help              Show this message",
    ].join("\n"),
  );
  process.exit(0);
}

const ROOT = resolve(import.meta.dirname!, "..");
const DEFAULT_LOCALES_ROOT = resolve(ROOT, "apps/web/src/locales");
const SOURCE_LOCALE = cli.source!;
const TARGET_LOCALE = cli.target!;

const sourceDirOverride = cli["source-dir"];
const targetDirOverride = cli["target-dir"];
if ((sourceDirOverride && !targetDirOverride) || (!sourceDirOverride && targetDirOverride)) {
  console.error("[i18n] --source-dir and --target-dir must be passed together.");
  process.exit(1);
}

const SOURCE_DIR = sourceDirOverride
  ? resolve(sourceDirOverride)
  : resolve(DEFAULT_LOCALES_ROOT, SOURCE_LOCALE);
const TARGET_DIR = targetDirOverride
  ? resolve(targetDirOverride)
  : resolve(DEFAULT_LOCALES_ROOT, TARGET_LOCALE);
const FORCE = cli.force ?? false;
const STRICT = cli.strict ?? false;

const onlyNs = cli.ns
  ? new Set(
      cli.ns
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    )
  : null;
const excludeNs = cli["exclude-ns"]
  ? new Set(
      cli["exclude-ns"]
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    )
  : new Set<string>();

if (!existsSync(SOURCE_DIR)) {
  console.error(`[i18n] Source locale directory missing: ${SOURCE_DIR}`);
  process.exit(1);
}
if (!existsSync(TARGET_DIR)) {
  console.error(`[i18n] Target locale directory missing: ${TARGET_DIR}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// JSON tree types + helpers
// ---------------------------------------------------------------------------

type JsonLeaf = string | number | boolean | null;
type JsonValue = JsonLeaf | JsonObject | JsonValue[];
interface JsonObject {
  [key: string]: JsonValue;
}

function isPlainObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function readJsonFile(path: string): JsonObject {
  if (!existsSync(path)) return {};
  const raw = readFileSync(path, "utf8").trim();
  if (raw.length === 0) return {};
  const parsed = JSON.parse(raw) as unknown;
  if (!isPlainObject(parsed)) {
    throw new Error(`[i18n] Expected an object at root of ${path}`);
  }
  return parsed;
}

function stableStringify(obj: JsonObject): string {
  // Match Phase 7 / existing-file convention: top-level keys sorted, 2-space
  // indent, trailing newline. Nested keys are emitted in en-US source order so
  // the diff against the source bundle stays readable.
  const sortedTop: JsonObject = {};
  for (const k of Object.keys(obj).sort()) {
    sortedTop[k] = obj[k]!;
  }
  return `${JSON.stringify(sortedTop, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Walking helpers
// ---------------------------------------------------------------------------

interface LeafPath {
  /** dot-joined key path used for logging only. */
  display: string;
  /** raw segments — handles keys that contain dots. */
  segments: string[];
  /** the source string at this leaf. */
  sourceValue: string;
  /** the existing value at the same path in target (may be undefined / "" / non-string). */
  targetValue: JsonValue | undefined;
}

function collectLeaves(
  source: JsonValue,
  target: JsonValue | undefined,
  segments: string[],
  out: LeafPath[],
): void {
  if (typeof source === "string") {
    out.push({
      display: segments.join("."),
      segments: [...segments],
      sourceValue: source,
      targetValue: typeof target === "undefined" ? undefined : target,
    });
    return;
  }
  if (isPlainObject(source)) {
    const targetObj = isPlainObject(target) ? target : undefined;
    for (const [k, v] of Object.entries(source)) {
      collectLeaves(v, targetObj?.[k], [...segments, k], out);
    }
    return;
  }
  // Arrays / numbers / booleans / null — surface as no-op leaves so the
  // round-trip preserves them. We don't translate non-strings.
}

function getAt(obj: JsonObject, segments: string[]): JsonValue | undefined {
  let cur: JsonValue | undefined = obj;
  for (const seg of segments) {
    if (!isPlainObject(cur)) return undefined;
    cur = cur[seg];
  }
  return cur;
}

function setAt(obj: JsonObject, segments: string[], value: JsonValue): void {
  let cur: JsonObject = obj;
  for (let i = 0; i < segments.length - 1; i++) {
    const seg = segments[i]!;
    const next = cur[seg];
    if (isPlainObject(next)) {
      cur = next;
    } else {
      const fresh: JsonObject = {};
      cur[seg] = fresh;
      cur = fresh;
    }
  }
  cur[segments[segments.length - 1]!] = value;
}

// ---------------------------------------------------------------------------
// "Should we translate this leaf?" decision
// ---------------------------------------------------------------------------

const PLACEHOLDER_ONLY_RE = /^\s*(\{\{[^}]+\}\}\s*)+$/;
const PUNCT_ONLY_RE = /^[\s\p{P}\p{S}]+$/u;

function looksUntranslatable(s: string): boolean {
  // Pure placeholder or pure punctuation — nothing to localize.
  if (PLACEHOLDER_ONLY_RE.test(s)) return true;
  if (PUNCT_ONLY_RE.test(s)) return true;
  // Single character or empty — can't meaningfully translate.
  if (s.trim().length < 2) return true;
  // Strip placeholders + punctuation/whitespace; if nothing meaningful is
  // left (e.g. "{{label}} #{{index}}"), treat as untranslatable scaffolding.
  const stripped = s
    .replace(/\{\{[^}]+\}\}/g, "")
    .replace(/[\s\p{P}\p{S}]+/gu, "")
    .trim();
  if (stripped.length < 2) return true;
  return false;
}

function shouldTranslate(leaf: LeafPath): boolean {
  const src = leaf.sourceValue;
  const tgt = leaf.targetValue;

  if (FORCE) {
    // Even with --force, never "translate" a string that has no translatable content.
    return !looksUntranslatable(src);
  }

  // Already populated (non-empty string, not equal to source) -> skip.
  if (typeof tgt === "string" && tgt.length > 0 && tgt !== src) return false;

  // Empty / missing -> needs translation, unless source is untranslatable.
  if (typeof tgt !== "string" || tgt.length === 0) {
    return !looksUntranslatable(src);
  }

  // tgt === src (literal copy of source). Two cases:
  //   1. Source is genuinely the same in both languages (e.g. "Slug",
  //      "{{label}} #{{index}}", proper nouns) — accept it, don't churn.
  //   2. Source was never translated (a Phase 7 dump that copy-pasted en-US
  //      values into es-MX) — translate it.
  // We can't reliably distinguish these from the file alone. Heuristic: if
  // the source is "short and lacks whitespace" treat it as case 1. Anything
  // with multiple words or >=5 chars likely needs a real translation.
  if (tgt === src) {
    if (looksUntranslatable(src)) return false;
    const trimmed = src.trim();
    const hasWhitespace = /\s/.test(trimmed);
    if (!hasWhitespace && trimmed.length < 5) return false;
    return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Validation: placeholders + <Trans> numeric tags must survive the round-trip
// ---------------------------------------------------------------------------

const PLACEHOLDER_RE = /\{\{[^}]+\}\}/g;
const TRANS_OPEN_RE = /<(\d+)>/g;
const TRANS_CLOSE_RE = /<\/(\d+)>/g;

function multisetCount(re: RegExp, s: string): Map<string, number> {
  const m = new Map<string, number>();
  for (const match of s.matchAll(re)) {
    const key = match[0];
    m.set(key, (m.get(key) ?? 0) + 1);
  }
  return m;
}

function multisetEqual(a: Map<string, number>, b: Map<string, number>): boolean {
  if (a.size !== b.size) return false;
  for (const [k, v] of a) {
    if (b.get(k) !== v) return false;
  }
  return true;
}

interface ValidationResult {
  ok: boolean;
  reason?: string;
}

function validateTranslation(source: string, translated: string): ValidationResult {
  const srcPh = multisetCount(PLACEHOLDER_RE, source);
  const tgtPh = multisetCount(PLACEHOLDER_RE, translated);
  if (!multisetEqual(srcPh, tgtPh)) {
    return {
      ok: false,
      reason: `placeholder mismatch: src=${[...srcPh.keys()].join(",") || "(none)"} target=${[...tgtPh.keys()].join(",") || "(none)"}`,
    };
  }
  const srcOpen = multisetCount(TRANS_OPEN_RE, source);
  const tgtOpen = multisetCount(TRANS_OPEN_RE, translated);
  if (!multisetEqual(srcOpen, tgtOpen)) {
    return { ok: false, reason: `<Trans> open tag mismatch` };
  }
  const srcClose = multisetCount(TRANS_CLOSE_RE, source);
  const tgtClose = multisetCount(TRANS_CLOSE_RE, translated);
  if (!multisetEqual(srcClose, tgtClose)) {
    return { ok: false, reason: `<Trans> close tag mismatch` };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Provider call with retry / backoff
// ---------------------------------------------------------------------------

interface ProviderCallResult {
  text: string;
  model: string;
}

const provider = getTranslationProvider();

function getErrorNumber(err: unknown, field: "status" | "statusCode"): number | undefined {
  if (!isPlainObject(err)) return undefined;
  const value = err[field];
  return typeof value === "number" ? value : undefined;
}

function getErrorCode(err: unknown): string | undefined {
  if (!isPlainObject(err)) return undefined;
  const value = err.code;
  return typeof value === "string" ? value : undefined;
}

function isTransientProviderError(err: unknown): boolean {
  const status = getErrorNumber(err, "status") ?? getErrorNumber(err, "statusCode");
  if (status !== undefined) {
    return status === 408 || status === 429 || (status >= 500 && status <= 599);
  }

  const code = getErrorCode(err);
  if (
    code === "ECONNRESET" ||
    code === "ECONNREFUSED" ||
    code === "ETIMEDOUT" ||
    code === "EAI_AGAIN" ||
    code === "UND_ERR_CONNECT_TIMEOUT" ||
    code === "UND_ERR_HEADERS_TIMEOUT" ||
    code === "UND_ERR_BODY_TIMEOUT"
  ) {
    return true;
  }

  const message = err instanceof Error ? err.message : String(err);
  return /\b(fetch failed|network|timeout|rate limit)\b/i.test(message);
}

async function callProvider(
  source: string,
  contentKind: "json" | "plaintext",
): Promise<ProviderCallResult> {
  const delays = [1000, 2000, 4000];
  let lastErr: unknown;
  for (let attempt = 0; attempt <= delays.length; attempt++) {
    try {
      const r = await provider.translate({
        source,
        sourceLocale: SOURCE_LOCALE,
        targetLocale: TARGET_LOCALE,
        contentKind,
      });
      return { text: r.text, model: r.model };
    } catch (err) {
      lastErr = err;
      const message = err instanceof Error ? err.message : String(err);
      if (attempt === delays.length || !isTransientProviderError(err)) {
        throw err;
      }
      const wait = delays[attempt]!;
      console.warn(
        `[i18n]   provider error (attempt ${attempt + 1}/${delays.length + 1}), retrying in ${wait}ms: ${message}`,
      );
      await new Promise((res) => setTimeout(res, wait));
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error("provider call failed");
}

// ---------------------------------------------------------------------------
// Bundle translation: build a "needed-keys-only" object, send as JSON,
// merge the response back in by leaf-path.
// ---------------------------------------------------------------------------

interface BundleResult {
  translated: Map<string, string>; // joined-display-path -> translated string
  parseFallbackUsed: boolean;
}

function buildSubsetObject(leaves: LeafPath[]): JsonObject {
  const out: JsonObject = {};
  for (const leaf of leaves) {
    setAt(out, leaf.segments, leaf.sourceValue);
  }
  return out;
}

function flattenStrings(obj: JsonValue, prefix: string[], out: Map<string, string>): void {
  if (typeof obj === "string") {
    out.set(prefix.join(" "), obj);
    return;
  }
  if (isPlainObject(obj)) {
    for (const [k, v] of Object.entries(obj)) {
      flattenStrings(v, [...prefix, k], out);
    }
  }
}

function stripCodeFences(s: string): string {
  // The prompt explicitly forbids fences but models sometimes wrap anyway.
  const trimmed = s.trim();
  const fence = /^```(?:json)?\s*([\s\S]*?)\s*```$/;
  const m = trimmed.match(fence);
  return m?.[1] ? m[1].trim() : trimmed;
}

async function translateBundle(namespace: string, leaves: LeafPath[]): Promise<BundleResult> {
  const subset = buildSubsetObject(leaves);
  const sourceJson = JSON.stringify(subset, null, 2);

  let parseFallbackUsed = false;
  const out = new Map<string, string>();

  // ---- Pass 1: bundle as JSON ------------------------------------------
  try {
    const { text } = await callProvider(sourceJson, "json");
    let parsed: unknown;
    try {
      parsed = JSON.parse(stripCodeFences(text));
    } catch (parseErr) {
      throw new Error(
        `JSON parse failed: ${parseErr instanceof Error ? parseErr.message : String(parseErr)}`,
      );
    }
    if (!isPlainObject(parsed)) {
      throw new Error("provider returned non-object JSON");
    }
    const flatTranslated = new Map<string, string>();
    flattenStrings(parsed as JsonValue, [], flatTranslated);
    // Map back by leaf segments
    for (const leaf of leaves) {
      const k = leaf.segments.join(" ");
      const v = flatTranslated.get(k);
      if (typeof v === "string") {
        out.set(leaf.display, v);
      }
    }
    if (out.size === 0) {
      throw new Error("provider response did not contain any expected keys");
    }
    if (out.size < leaves.length) {
      console.warn(
        `[i18n]   ${namespace}: bundle returned ${out.size}/${leaves.length} keys, will plaintext-fill the rest.`,
      );
    }
  } catch (err) {
    parseFallbackUsed = true;
    console.warn(
      `[i18n]   ${namespace}: bundle JSON path failed (${err instanceof Error ? err.message : String(err)}), falling back to per-key plaintext.`,
    );
    out.clear();
  }

  // ---- Pass 2: per-key plaintext for any leaf still missing ------------
  const missing = leaves.filter((leaf) => !out.has(leaf.display));
  for (const leaf of missing) {
    try {
      const { text } = await callProvider(leaf.sourceValue, "plaintext");
      out.set(leaf.display, text.trim());
    } catch (err) {
      console.warn(
        `[i18n]   ${namespace}: plaintext fallback failed for "${leaf.display}": ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  return { translated: out, parseFallbackUsed };
}

// ---------------------------------------------------------------------------
// Validation + retry pass
// ---------------------------------------------------------------------------

interface NamespaceSummary {
  namespace: string;
  needed: number;
  written: number;
  warnings: number;
  dropped: number;
  parseFallback: boolean;
  partial: boolean;
}

async function processNamespace(file: string): Promise<NamespaceSummary> {
  const namespace = basename(file, ".json");
  const sourcePath = resolve(SOURCE_DIR, file);
  const targetPath = resolve(TARGET_DIR, file);
  const source = readJsonFile(sourcePath);
  const target = readJsonFile(targetPath);

  const leaves: LeafPath[] = [];
  collectLeaves(source, target, [], leaves);
  const needsTranslation = leaves.filter(shouldTranslate);

  const summary: NamespaceSummary = {
    namespace,
    needed: needsTranslation.length,
    written: 0,
    warnings: 0,
    dropped: 0,
    parseFallback: false,
    partial: false,
  };

  if (needsTranslation.length === 0) {
    console.log(`[i18n] ${namespace}: nothing to translate (already populated).`);
    // Still rewrite the target file to normalize formatting, but only if it
    // already exists; never create a new file when there's nothing to write.
    if (existsSync(targetPath)) {
      writeFileSync(targetPath, stableStringify(target), "utf8");
    }
    return summary;
  }

  console.log(
    `[i18n] ${namespace}: ${needsTranslation.length} key(s) need translation. Calling provider...`,
  );

  let bundle: BundleResult;
  try {
    bundle = await translateBundle(namespace, needsTranslation);
  } catch (err) {
    console.error(
      `[i18n] ${namespace}: bundle failed entirely (${err instanceof Error ? err.message : String(err)}). Marking PARTIAL.`,
    );
    summary.partial = true;
    return summary;
  }
  summary.parseFallback = bundle.parseFallbackUsed;

  // ---- Validate + retry per-key ------------------------------------------
  for (const leaf of needsTranslation) {
    let value = bundle.translated.get(leaf.display);
    if (typeof value !== "string" || value.length === 0) {
      console.warn(`[i18n]   ${namespace}: missing translation for "${leaf.display}"`);
      summary.dropped += 1;
      summary.partial = true;
      continue;
    }
    let validation = validateTranslation(leaf.sourceValue, value);
    if (!validation.ok) {
      console.warn(
        `[i18n]   ${namespace}: validation warning for "${leaf.display}" — ${validation.reason}. Retrying as plaintext...`,
      );
      summary.warnings += 1;
      try {
        const { text } = await callProvider(leaf.sourceValue, "plaintext");
        const retryValue = text.trim();
        validation = validateTranslation(leaf.sourceValue, retryValue);
        if (validation.ok) {
          value = retryValue;
        } else if (STRICT) {
          console.warn(
            `[i18n]   ${namespace}: STRICT — dropping "${leaf.display}" (${validation.reason})`,
          );
          summary.dropped += 1;
          summary.partial = true;
          continue;
        } else {
          console.warn(
            `[i18n]   ${namespace}: keeping translation despite validation failure for "${leaf.display}" (${validation.reason}). Run with --strict to drop.`,
          );
          value = retryValue;
        }
      } catch (err) {
        if (STRICT) {
          console.warn(
            `[i18n]   ${namespace}: STRICT — dropping "${leaf.display}" (retry failed: ${err instanceof Error ? err.message : String(err)})`,
          );
          summary.dropped += 1;
          summary.partial = true;
          continue;
        }
        console.warn(
          `[i18n]   ${namespace}: retry failed for "${leaf.display}", keeping original translation. ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    setAt(target, leaf.segments, value);
    summary.written += 1;
  }

  // ---- Verify key parity vs source --------------------------------------
  // The target object should contain every leaf path that source contains.
  // Anything missing is a dropped translation; anything extra is unexpected.
  const sourceLeaves: LeafPath[] = [];
  collectLeaves(source, undefined, [], sourceLeaves);
  for (const sl of sourceLeaves) {
    const tv = getAt(target, sl.segments);
    if (typeof tv !== "string") {
      // Re-create as empty string so i18next falls back to en-US gracefully.
      setAt(target, sl.segments, "");
    }
  }

  writeFileSync(targetPath, stableStringify(target), "utf8");
  console.log(
    `[i18n] ${namespace}: wrote ${summary.written}/${summary.needed} translation(s) -> ${targetPath}`,
  );

  return summary;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const start = Date.now();
  const files = readdirSync(SOURCE_DIR)
    .filter((f) => f.endsWith(".json"))
    .filter((f) => {
      const ns = basename(f, ".json");
      if (onlyNs && !onlyNs.has(ns)) return false;
      if (excludeNs.has(ns)) return false;
      return true;
    })
    .sort();

  if (files.length === 0) {
    console.error(`[i18n] No JSON files matched in ${SOURCE_DIR}.`);
    process.exit(1);
  }

  console.log(
    `[i18n] Translating ${files.length} namespace(s) ${SOURCE_LOCALE} -> ${TARGET_LOCALE}` +
      `${FORCE ? " (--force)" : ""}${STRICT ? " (--strict)" : ""}`,
  );

  const summaries: NamespaceSummary[] = [];
  for (const f of files) {
    try {
      summaries.push(await processNamespace(f));
    } catch (err) {
      console.error(`[i18n] ${f}: FATAL — ${err instanceof Error ? err.message : String(err)}`);
      summaries.push({
        namespace: basename(f, ".json"),
        needed: 0,
        written: 0,
        warnings: 0,
        dropped: 0,
        parseFallback: false,
        partial: true,
      });
    }
  }

  const elapsedMs = Date.now() - start;
  console.log("");
  console.log("[i18n] ============================================================");
  console.log("[i18n] Summary");
  console.log("[i18n] ============================================================");
  for (const s of summaries) {
    const status = s.partial ? "PARTIAL" : s.needed === 0 ? "OK (no-op)" : "OK";
    console.log(
      `[i18n]   ${s.namespace.padEnd(14)} status=${status.padEnd(11)} ` +
        `translated=${s.written}/${s.needed}  warnings=${s.warnings}  dropped=${s.dropped}  ` +
        `bundleFallback=${s.parseFallback ? "yes" : "no"}`,
    );
  }
  const totals = summaries.reduce(
    (acc, s) => ({
      needed: acc.needed + s.needed,
      written: acc.written + s.written,
      warnings: acc.warnings + s.warnings,
      dropped: acc.dropped + s.dropped,
    }),
    { needed: 0, written: 0, warnings: 0, dropped: 0 },
  );
  console.log(
    `[i18n]   TOTAL          translated=${totals.written}/${totals.needed}  ` +
      `warnings=${totals.warnings}  dropped=${totals.dropped}  ` +
      `runtime=${(elapsedMs / 1000).toFixed(1)}s`,
  );
  console.log(
    "[i18n] (Token usage is not surfaced by the provider abstraction; estimate by source/target byte counts.)",
  );
}

main().catch((err) => {
  console.error("[i18n] Unhandled error:", err);
  process.exit(1);
});
