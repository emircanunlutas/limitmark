import "server-only";

export async function postResendEmail(init: RequestInit) {
  const response = await globalThis.fetch("https://api.resend.com/emails", init);
  const retryAfter = response.status === 429 || response.status === 503
    ? response.headers.get("retry-after")
    : null;
  return { response, retryAfter };
}
