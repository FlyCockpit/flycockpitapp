import { z } from "zod";

export function originUrl(label: string) {
  return z
    .url()
    .refine(
      (value) => {
        const parsed = new URL(value);
        return parsed.protocol === "http:" || parsed.protocol === "https:";
      },
      { message: `${label} must use http or https.` },
    )
    .refine(
      (value) => {
        const parsed = new URL(value);
        return !parsed.username && !parsed.password;
      },
      { message: `${label} must not include credentials.` },
    )
    .refine(
      (value) => {
        const parsed = new URL(value);
        return parsed.pathname === "/" && !parsed.search && !parsed.hash;
      },
      { message: `${label} must be an origin only, with no path, query, or hash.` },
    )
    .transform((value) => new URL(value).origin);
}
