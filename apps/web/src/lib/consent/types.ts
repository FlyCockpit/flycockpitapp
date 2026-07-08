/**
 * Consent type model. Kept dependency-free (no React, no DOM-only types) so
 * the core engine can be unit-tested and, if ever needed, promoted to a shared
 * package without dragging the web app along.
 */

type ConsentCategory = "necessary" | "functional" | "analytics" | "marketing";

/** Categories the visitor can toggle. `necessary` is always on and never stored. */
export type OptionalCategory = Exclude<ConsentCategory, "necessary">;
export const OPTIONAL_CATEGORIES = [
  "functional",
  "analytics",
  "marketing",
] as const satisfies readonly OptionalCategory[];

/** Per-category decision. `necessary` is implied `true` and not represented here. */
export type ConsentState = Record<OptionalCategory, boolean>;

/** Shape persisted in the first-party consent cookie (JSON-encoded). */
export type ConsentCookie = {
  /** Policy version this decision was made under. */
  v: number;
  /** Epoch ms when the decision was recorded. */
  ts: number;
  /** Stable anonymous id; correlates the client decision with the server record. */
  id: string;
  /** Per-category decision. */
  cats: ConsentState;
};

export type AdapterName = "gtag" | "metaPixel" | "script" | "callback";

/**
 * One third-party tag the downstream developer wants gated behind consent.
 * This is the *only* surface a non-technical integrator edits — never the
 * gating engine. See {@link file://./registry.ts}.
 */
export type ConsentTag = {
  /** Stable unique id; also the dedupe key for the injected <script>. */
  id: string;
  /** Which consent category must be granted before this tag may load. */
  category: OptionalCategory;
  /** Which built-in adapter knows how to load/unload this tag. */
  adapter: AdapterName;
  /** Adapter-specific config (`measurementId`, `pixelId`, `src`, `mode`, …). */
  params?: Record<string, unknown>;
  /** Only read by the `callback` adapter — for first-party cookies the app sets itself. */
  onGrant?: () => void;
  onRevoke?: () => void;
};
