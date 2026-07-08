import { DEFAULT_LOCALE, isSupportedLocale } from "./config";

/**
 * Inputs the `/$lang` route's `beforeLoad` needs to make a redirect decision.
 * Mirrors the shape of the args TanStack Router passes (typed loosely so this
 * helper can be unit-tested without dragging in router types).
 */
export interface RedirectToDefaultArgs {
  params: { lang: string };
  location: {
    pathname: string;
    searchStr: string;
    hash: string;
  };
}

export interface RedirectInstruction {
  /** The full URL (path + search + hash) to redirect to. */
  href: string;
  replace: true;
}

/**
 * Pure helper that decides whether the visitor is on a valid `/$lang/...`
 * URL — and if not, what URL to redirect to. Returns `null` when the lang
 * segment is supported (no redirect needed).
 *
 * Lifted out of the route file so it can be unit-tested without importing
 * React-only modules. The route's `beforeLoad` calls this and either returns
 * undefined or `throw redirect(...)` with the returned instruction.
 */
export function decideLocaleRedirect(args: RedirectToDefaultArgs): RedirectInstruction | null {
  const { params, location } = args;
  if (isSupportedLocale(params.lang)) return null;

  const segments = location.pathname.split("/").filter(Boolean);
  const looksLikeLocale = /^[a-z]{2,3}(-[A-Z]{2})?$/.test(params.lang);
  const rest = looksLikeLocale ? segments.slice(1) : segments;
  const suffix = rest.length > 0 ? `/${rest.join("/")}` : "";
  const href = `/${DEFAULT_LOCALE}${suffix}${location.searchStr}${location.hash ? `#${location.hash}` : ""}`;
  return { href, replace: true };
}
