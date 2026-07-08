/**
 * Locale-aware Zod error map.
 *
 * Wires Zod v4's `z.config({ customError })` to look up validation messages
 * from the `validation` i18next namespace. Once installed, every bare
 * `z.string().email()` / `.min(8)` / etc. failure renders in the active
 * locale automatically — no per-form change needed.
 *
 * Why we don't use `zod-i18n-map`: that library is built for Zod v3's issue
 * shape (`code: "too_small", type: "string"`). Zod v4 changed the shape
 * (`code: "too_small", origin: "string"`, plus `invalid_format` replacing
 * `invalid_string`), so the v3 library mis-keys lookups. Zod v4 ships
 * first-class config support — leverage that.
 */
import type { i18n as I18nInstance } from "i18next";
import { z } from "zod";

let installed = false;
let activeI18n: I18nInstance | null = null;
let activeListener: (() => void) | null = null;

type Issue = {
  readonly code?: string;
  readonly input?: unknown;
  readonly path?: PropertyKey[];
  // Fields that may be present depending on the discriminator. Typed loosely
  // because Zod's $ZodRawIssue is a union and the map needs to read whichever
  // fields the active issue happens to carry.
  readonly expected?: string;
  readonly origin?: string;
  readonly minimum?: number | bigint;
  readonly maximum?: number | bigint;
  readonly format?: string;
  readonly pattern?: string;
  readonly prefix?: string;
  readonly suffix?: string;
  readonly includes?: string;
  readonly divisor?: number;
  readonly values?: ReadonlyArray<unknown>;
  readonly keys?: ReadonlyArray<string>;
};

/**
 * Origin → JSON-key mapping for `too_small` / `too_big`. Mirrors Zod v4's
 * `Sizable` table in `zod/v4/locales/en.js`. Anything not listed falls back
 * to the `number` key (which renders the bare numeric bound).
 */
const SIZE_ORIGIN_KEYS = new Set([
  "string",
  "number",
  "int",
  "bigint",
  "date",
  "array",
  "set",
  "file",
]);

function sizeOriginKey(origin: string | undefined): string {
  if (origin && SIZE_ORIGIN_KEYS.has(origin)) return origin;
  return "number";
}

/**
 * Best-effort detection of "this was a missing/undefined value" so a form
 * field with no input shows "This field is required." instead of the generic
 * "Expected string." copy.
 */
function isMissingValue(issue: Issue): boolean {
  return issue.code === "invalid_type" && issue.input === undefined;
}

function buildErrorMap(i18n: I18nInstance) {
  const t = i18n.getFixedT(null, "validation");

  return (issue: Issue): { message: string } | string | undefined => {
    switch (issue.code) {
      case "invalid_type": {
        if (isMissingValue(issue)) return { message: t("required") };
        return {
          message: t("invalidType", { expected: issue.expected ?? "value" }),
        };
      }
      case "too_small": {
        const key = `tooSmall.${sizeOriginKey(issue.origin)}`;
        return {
          message: t(key, { minimum: String(issue.minimum ?? "") }),
        };
      }
      case "too_big": {
        const key = `tooBig.${sizeOriginKey(issue.origin)}`;
        return {
          message: t(key, { maximum: String(issue.maximum ?? "") }),
        };
      }
      case "invalid_format": {
        const format = issue.format ?? "regex";
        // Map Zod v4 format codes to JSON keys (snake_case → camelCase).
        const formatKeyMap: Record<string, string> = {
          starts_with: "startsWith",
          ends_with: "endsWith",
        };
        const key = `invalidString.${formatKeyMap[format] ?? format}`;
        return {
          message: t(key, {
            prefix: issue.prefix ?? "",
            suffix: issue.suffix ?? "",
            includes: issue.includes ?? "",
            pattern: issue.pattern ?? "",
            // Fall through to the generic "Format is invalid." copy if the
            // specific format key isn't translated yet.
            defaultValue: t("invalidString.regex"),
          }),
        };
      }
      case "invalid_value": {
        // Zod v4 collapsed v3's `invalid_enum_value` and `invalid_literal`
        // into one issue keyed on `values.length`. Single-value = literal,
        // multi-value = enum.
        const values = issue.values ?? [];
        if (values.length === 1) {
          return { message: t("invalidLiteral", { expected: String(values[0]) }) };
        }
        return {
          message: t("invalidEnum", { options: values.map(String).join(", ") }),
        };
      }
      case "not_multiple_of": {
        return {
          message: t("notMultipleOf", { multipleOf: String(issue.divisor ?? "") }),
        };
      }
      case "unrecognized_keys": {
        return {
          message: t("unrecognizedKeys", { keys: (issue.keys ?? []).join(", ") }),
        };
      }
      case "invalid_union":
        return { message: t("invalidUnion") };
      case "invalid_key":
        return { message: t("invalidKey") };
      case "invalid_element":
        return { message: t("invalidElement") };
      case "custom":
        return { message: t("custom") };
      default:
        // Fall through to Zod's default message — return undefined so the
        // built-in localeError or message generator runs.
        return undefined;
    }
  };
}

/**
 * Install the i18n-aware Zod error map. Idempotent — safe to call multiple
 * times (HMR re-imports modules in dev). Subsequent calls swap the active
 * i18n instance and re-bind the language-change listener.
 */
export function installZodErrorMap(i18n: I18nInstance): void {
  // Re-bind the customError to a fresh closure that captures the new
  // i18n.t. We call this both on first install and on every languageChanged
  // event so the map always reads the current language's resources.
  const apply = () => {
    z.config({ customError: buildErrorMap(i18n) });
  };

  apply();

  if (installed && activeI18n === i18n) {
    // Same instance — listener is already wired, just refreshed the map.
    return;
  }

  if (activeI18n && activeListener) {
    // A previous instance is registered. Drop its listener (rare — typically
    // only happens in tests or during HMR with a swapped i18n instance).
    activeI18n.off("languageChanged", activeListener);
  }

  i18n.on("languageChanged", apply);
  activeI18n = i18n;
  activeListener = apply;
  installed = true;
}
