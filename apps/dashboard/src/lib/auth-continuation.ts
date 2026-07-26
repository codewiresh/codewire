const APP_ORIGIN = "https://codewire.invalid";

/**
 * Normalize an application-relative post-login target.
 *
 * Login continuations are controlled by the browser URL, so never reflect an
 * absolute or protocol-relative target into window.location after sign-in.
 */
export function safeAuthContinuation(value: unknown): string | undefined {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    value.startsWith("//")
  ) {
    return undefined;
  }

  try {
    const target = new URL(value, APP_ORIGIN);
    if (target.origin !== APP_ORIGIN) return undefined;
    return `${target.pathname}${target.search}${target.hash}`;
  } catch {
    return undefined;
  }
}
