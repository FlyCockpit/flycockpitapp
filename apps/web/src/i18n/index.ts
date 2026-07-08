import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import {
  DEFAULT_LOCALE,
  isSupportedLocale,
  type Locale,
  NAMESPACES,
  SUPPORTED_LOCALES,
} from "./config";
import { installZodErrorMap } from "./zod";

type ResourceBundle = Record<string, unknown>;
type ResourceTree = Record<string, Record<string, ResourceBundle>>;

// Only the default locale is bundled eagerly. Keeping it in the initial bundle
// means first paint and the synchronous Zod error-map install (below) never
// wait on a network round-trip, and the `fallbackLng` always has its strings
// on hand. Every OTHER locale is split into its own chunk and fetched on
// demand by `loadLocale()` — so adding a language costs nothing in the base
// bundle. See the i18n locale-splitting setup.
//
// `import.meta.glob` needs a *static* pattern, so the eager glob hardcodes the
// default-locale folder. If you change DEFAULT_LOCALE you must update this glob
// (the dev-time assert below will flag the mismatch).
const eagerDefaultModules = import.meta.glob("../locales/en-US/*.json", {
  eager: true,
  import: "default",
}) as Record<string, ResourceBundle>;

// Lazy loaders for every locale (the default included, harmlessly). Each entry
// is a `() => import("../locales/<locale>/<ns>.json")` that the bundler emits
// as a separate chunk; nothing here ships in the base bundle.
const lazyLocaleModules = import.meta.glob("../locales/*/*.json", {
  import: "default",
}) as Record<string, () => Promise<ResourceBundle>>;

if (import.meta.env.DEV && DEFAULT_LOCALE !== "en-US") {
  console.warn(
    `[i18n] DEFAULT_LOCALE is "${DEFAULT_LOCALE}" but the eager locale glob in i18n/index.ts is pinned to "en-US". ` +
      "Update the import.meta.glob pattern so the default locale ships in the base bundle.",
  );
}

function parseLocalePath(path: string): { locale: string; ns: string } | undefined {
  const match = /\/locales\/([^/]+)\/([^/]+)\.json$/.exec(path);
  if (!match?.[1] || !match[2]) return undefined;
  return { locale: match[1], ns: match[2] };
}

function buildEagerResources(): ResourceTree {
  const out: ResourceTree = {};
  for (const [path, mod] of Object.entries(eagerDefaultModules)) {
    const parsed = parseLocalePath(path);
    if (!parsed) continue;
    out[parsed.locale] ??= {};
    out[parsed.locale][parsed.ns] = mod;
  }
  return out;
}

const resources = buildEagerResources();

// Locales whose bundles are already registered with i18next. Seeded with every
// eagerly-bundled locale so we never re-fetch the default.
const loadedLocales = new Set<string>(Object.keys(resources));

/**
 * Fetch and register a locale's namespace bundles on demand. Idempotent and
 * safe to call repeatedly (concurrent calls dedupe via the in-flight map).
 * After the bundles register, react-i18next re-renders subscribed components,
 * so a non-default-locale visitor sees the default-language fallback for the
 * few milliseconds the chunk takes to load, then the localized strings.
 *
 * A failed load (a rejected chunk `import()` — plausible during a PWA
 * deploy/cache transition or a transient network blip) is recoverable: the
 * locale is NOT marked loaded and the in-flight entry is cleared either way, so
 * the next `languageChanged` (or an explicit retry) re-attempts the fetch
 * instead of being pinned forever to the same rejected promise.
 */
const inFlight = new Map<string, Promise<void>>();
function loadLocale(locale: string): Promise<void> {
  if (loadedLocales.has(locale)) return Promise.resolve();
  const existing = inFlight.get(locale);
  if (existing) return existing;

  const task = Promise.all(
    Object.entries(lazyLocaleModules)
      .filter(([path]) => parseLocalePath(path)?.locale === locale)
      .map(async ([path, load]) => {
        const parsed = parseLocalePath(path);
        if (!parsed) return;
        const bundle = await load();
        // `deep`+`overwrite` so a re-register is a no-op rather than a merge bug.
        i18n.addResourceBundle(locale, parsed.ns, bundle, true, true);
      }),
  )
    // Only mark the locale loaded once every namespace registered — a partial
    // or failed load must remain retryable.
    .then(() => {
      loadedLocales.add(locale);
    })
    // Always release the in-flight slot, success or failure, so a rejected load
    // never permanently blocks future attempts.
    .finally(() => {
      inFlight.delete(locale);
    });

  inFlight.set(locale, task);
  return task;
}

export function getInitialLocale(): Locale {
  if (typeof window === "undefined") return DEFAULT_LOCALE;
  // The URL wins. If the visitor lands on `/es-MX/dashboard` we want that to
  // beat whatever localStorage or the navigator says — the URL is the most
  // explicit signal.
  const fromPath = window.location.pathname.split("/")[1];
  if (fromPath && isSupportedLocale(fromPath)) return fromPath;
  const stored = window.localStorage.getItem("locale");
  if (stored && isSupportedLocale(stored)) return stored;
  const nav = window.navigator?.language;
  if (nav && isSupportedLocale(nav)) return nav;
  return DEFAULT_LOCALE;
}

/**
 * Custom i18next-browser-languagedetector entry that reads `/:lang/...` from
 * `window.location.pathname` first. Ordered ahead of `localStorage` and
 * `navigator` so a `/es-MX/...` URL beats every stored preference. The
 * `$lang` route layout already rewrites unknown locales to `DEFAULT_LOCALE`,
 * so anything we read here is guaranteed to be a supported value.
 */
const URL_PATH_DETECTOR = {
  name: "urlPath" as const,
  lookup(): string | undefined {
    if (typeof window === "undefined") return undefined;
    const segment = window.location.pathname.split("/")[1];
    return segment && isSupportedLocale(segment) ? segment : undefined;
  },
};

if (!i18n.isInitialized) {
  const detector = new LanguageDetector();
  detector.addDetector(URL_PATH_DETECTOR);

  // Every locale switch funnels through `i18n.changeLanguage` (the language
  // switcher, the user-locale sync hook, the change-language hook), which emits
  // `languageChanged`. Hooking it here covers all of them with one handler:
  // when a non-default locale becomes active and its bundles aren't loaded yet,
  // fetch them. i18next also emits this once on init for the detected initial
  // language, so a deep-linked `/es-MX/...` visit loads es-MX automatically.
  i18n.on("languageChanged", (lng) => {
    if (!isSupportedLocale(lng)) return;
    // Swallow + log here so a failed locale fetch doesn't surface as an
    // unhandled rejection. loadLocale() leaves the locale retryable, and the
    // visitor keeps the fallback strings until the next switch re-attempts it.
    void loadLocale(lng).catch((error) => {
      console.error(`[i18n] failed to load locale "${lng}"`, error);
    });
  });

  const initPromise = i18n
    .use(detector)
    .use(initReactI18next)
    .init({
      resources,
      fallbackLng: DEFAULT_LOCALE,
      supportedLngs: SUPPORTED_LOCALES as unknown as string[],
      ns: NAMESPACES as unknown as string[],
      defaultNS: "common",
      interpolation: { escapeValue: false },
      // The detection chain is split between this synchronous detector list
      // and the async `useUserLocaleSync()` hook. Order of precedence:
      //   1. `urlPath` — the URL is the most explicit signal. The `$lang`
      //      layout has already validated the segment by the time this runs.
      //   2. `localStorage` — an explicit "I picked this on this device"
      //      choice from the language switcher.
      //   3. `user.locale` (server-side, via `useUserLocaleSync`) — a
      //      signed-in user's preference; resolves async after the session
      //      query loads, so it cannot live in this detector array. The hook
      //      navigates to `/${user.locale}/...` only when localStorage is
      //      empty, preserving the order described here.
      //   4. `navigator` — fall back to the device's UI language.
      //   5. `DEFAULT_LOCALE` — final fallback.
      detection: {
        order: ["urlPath", "localStorage", "navigator"],
        lookupLocalStorage: "locale",
        caches: ["localStorage"],
      },
      react: {
        useSuspense: false,
        // Lazy locales arrive AFTER `languageChanged` already fired (see
        // loadLocale), so we must re-render on the store's `added` event too —
        // otherwise a non-default-locale visitor would be stuck on the
        // fallback strings even after their bundle finished loading.
        bindI18nStore: "added",
      },
    });

  // Install the locale-aware Zod error map once init resolves so every form
  // schema's validation messages render in the active language. Resources are
  // eager-globbed above so this resolves synchronously in practice. Phase 6.
  void initPromise.then(() => installZodErrorMap(i18n));
}

export default i18n;
