/**
 * Validate a `redirectTo` search param so it can only point back into the
 * current locale's own routes (never to an external origin, never back to the
 * auth pages themselves). Falls back to the locale's dashboard.
 */
export function safeRedirectTo(value: unknown, lang: string): string {
  if (typeof value !== "string") return `/${lang}/dashboard`;
  if (!value.startsWith(`/${lang}/`)) return `/${lang}/dashboard`;
  if (value.startsWith(`/${lang}/login`)) return `/${lang}/dashboard`;
  if (value.startsWith(`/${lang}/signup`)) return `/${lang}/dashboard`;
  return value;
}
