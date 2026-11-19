const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const GOOGLE_IAM_CREDENTIALS_ENDPOINT = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/";
const JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
const TOKEN_REFRESH_MARGIN_SECONDS = 60;
const MAX_ASSERTION_LIFETIME_SECONDS = 3600;

type ServiceAccountCredentials = {
  client_email: string;
  private_key: string;
  private_key_id: string;
  token_uri?: string;
};

type CachedToken = {
  value: string;
  expiresAt: number;
};

type GoogleIdTokenDependencies = {
  fetch?: typeof fetch;
  now?: () => number;
  subtle?: SubtleCrypto;
};

function encodeBase64url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function encodeUtf8Base64url(value: string): string {
  return encodeBase64url(new TextEncoder().encode(value));
}

function decodeBase64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("google-token-encoding");
  const padded = value.replace(/-/gu, "+").replace(/_/gu, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function readJsonObject(value: string): ServiceAccountCredentials {
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error("google-credentials-json"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("google-credentials-shape");
  const credentials = parsed as Record<string, unknown>;
  const clientEmail = credentials.client_email;
  const privateKey = credentials.private_key;
  const privateKeyId = credentials.private_key_id;
  const tokenUri = credentials.token_uri;
  if (typeof clientEmail !== "string" || !/^[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com$/u.test(clientEmail) ||
      typeof privateKey !== "string" || !privateKey.includes("-----BEGIN PRIVATE KEY-----") ||
      !privateKey.includes("-----END PRIVATE KEY-----") ||
      typeof privateKeyId !== "string" || !/^[A-Za-z0-9_-]{1,256}$/u.test(privateKeyId) ||
      (tokenUri !== undefined && tokenUri !== GOOGLE_TOKEN_ENDPOINT)) throw new Error("google-credentials-invalid");
  return { client_email: clientEmail, private_key: privateKey, private_key_id: privateKeyId, token_uri: GOOGLE_TOKEN_ENDPOINT };
}

function readJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("google-id-token-format");
  let payload: unknown;
  try { payload = JSON.parse(new TextDecoder().decode(decodeBase64url(parts[1]))); } catch { throw new Error("google-id-token-payload"); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("google-id-token-payload");
  return payload as Record<string, unknown>;
}

function pemToDer(privateKey: string): ArrayBuffer {
  const body = privateKey.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace(/\s/gu, "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(body)) throw new Error("google-private-key-encoding");
  const binary = atob(body);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

export function createGoogleIdTokenProvider(
  credentialsJson: string | undefined,
  audience: string,
  dependencies: GoogleIdTokenDependencies = {},
): () => Promise<string> {
  const requestFetch = dependencies.fetch ?? fetch;
  const now = dependencies.now ?? (() => Date.now());
  const subtle = dependencies.subtle ?? crypto.subtle;
  let credentials: ServiceAccountCredentials | undefined;
  let signingKey: CryptoKey | undefined;
  let cached: CachedToken | undefined;
  let inFlight: Promise<string> | undefined;

  return async function getToken(): Promise<string> {
    // Only the caller that STARTS an acquisition owns it and may clear it; callers that join an acquisition in flight must never clear it (doing so let a
    // third caller start a second concurrent acquisition while the first was still pending).
    let started: Promise<string> | undefined;
    try {
      if (!credentialsJson || !/^https:\/\/[a-z0-9.-]+$/iu.test(audience)) throw new Error("google-token-config");
      const currentSeconds = Math.floor(now() / 1000);
      if (cached && cached.expiresAt > currentSeconds + TOKEN_REFRESH_MARGIN_SECONDS) return cached.value;
      if (inFlight) return await inFlight;
      started = inFlight = (async () => {
        credentials ??= readJsonObject(credentialsJson);
        signingKey ??= await subtle.importKey(
          "pkcs8",
          pemToDer(credentials.private_key),
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
          false,
          ["sign"],
        );
        const issuedAt = Math.max(0, Math.floor(now() / 1000) - 30);
        const assertion = [
          encodeUtf8Base64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: credentials.private_key_id })),
          encodeUtf8Base64url(JSON.stringify({
            iss: credentials.client_email,
            scope: CLOUD_PLATFORM_SCOPE,
            aud: GOOGLE_TOKEN_ENDPOINT,
            iat: issuedAt,
            exp: issuedAt + MAX_ASSERTION_LIFETIME_SECONDS,
          })),
        ].join(".");
        const signature = await subtle.sign("RSASSA-PKCS1-v1_5", signingKey, new TextEncoder().encode(assertion));
        const signedAssertion = `${assertion}.${encodeBase64url(new Uint8Array(signature))}`;
        const tokenResponse = await requestFetch(GOOGLE_TOKEN_ENDPOINT, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ grant_type: JWT_GRANT_TYPE, assertion: signedAssertion }),
        });
        if (!tokenResponse.ok) throw new Error("google-access-token-http");
        const tokenBody = await tokenResponse.json() as { access_token?: unknown; expires_in?: unknown };
        if (typeof tokenBody.access_token !== "string" || !/^\S{1,8192}$/u.test(tokenBody.access_token) ||
            typeof tokenBody.expires_in !== "number" || !Number.isSafeInteger(tokenBody.expires_in) || tokenBody.expires_in <= 0) {
          throw new Error("google-access-token-response");
        }
        const idTokenResponse = await requestFetch(
          `${GOOGLE_IAM_CREDENTIALS_ENDPOINT}${encodeURIComponent(credentials.client_email)}:generateIdToken`,
          {
            method: "POST",
            headers: { authorization: `Bearer ${tokenBody.access_token}`, "content-type": "application/json" },
            body: JSON.stringify({ audience, includeEmail: true }),
          },
        );
        if (!idTokenResponse.ok) throw new Error("google-id-token-http");
        const idTokenBody = await idTokenResponse.json() as { token?: unknown };
        if (typeof idTokenBody.token !== "string" || idTokenBody.token.length > 8192) throw new Error("google-id-token-response");
        const payload = readJwtPayload(idTokenBody.token);
        if (payload.aud !== audience || typeof payload.exp !== "number" || !Number.isSafeInteger(payload.exp) ||
            payload.exp <= currentSeconds + TOKEN_REFRESH_MARGIN_SECONDS ||
            typeof payload.iat !== "number" || !Number.isSafeInteger(payload.iat) || payload.iat > currentSeconds + 60) {
          throw new Error("google-id-token-claims");
        }
        cached = { value: idTokenBody.token, expiresAt: payload.exp };
        return idTokenBody.token;
      })();
      return await started;
    } catch {
      cached = undefined;
      throw new Error("google-id-token-acquisition-failed");
    } finally {
      if (started !== undefined && inFlight === started) inFlight = undefined;
    }
  };
}
