export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function safeHref(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Email link must be an absolute HTTP(S) URL.");
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Email link must use HTTP or HTTPS.");
  }

  return escapeHtml(url.toString());
}
