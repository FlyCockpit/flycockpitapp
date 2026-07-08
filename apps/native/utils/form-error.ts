type ErrorMessageShape = {
  message?: unknown;
  error?: {
    message?: unknown;
    status?: unknown;
    code?: unknown;
  };
  status?: unknown;
  code?: unknown;
};

export function getErrorMessage(error: unknown): string | null {
  if (!error) return null;

  if (typeof error === "string") {
    return error;
  }

  if (Array.isArray(error)) {
    for (const issue of error) {
      const message = getErrorMessage(issue);
      if (message) {
        return message;
      }
    }
    return null;
  }

  if (typeof error === "object" && error !== null) {
    const maybeError = error as ErrorMessageShape;
    if (typeof maybeError.message === "string") {
      return maybeError.message;
    }
    if (typeof maybeError.error?.message === "string") {
      return maybeError.error.message;
    }
  }

  return null;
}

export function getAuthErrorMessage(error: unknown, fallback: string): string {
  const rawMessage = getErrorMessage(error);
  const lower = rawMessage?.toLowerCase() ?? "";

  if (lower.includes("email") && lower.includes("verif")) {
    return "Verify your email address before signing in. Check your inbox for the verification link.";
  }

  if (lower.includes("two") && lower.includes("factor")) {
    return "This account requires two-factor authentication. Use the web app to complete sign-in for now.";
  }

  return rawMessage || fallback;
}
