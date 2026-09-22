import { createHash, createHmac } from "node:crypto";
import { Agent, request } from "node:https";
import type { RequestOptions } from "node:https";

export type R2Target = { accountId: string; bucket: string };
export type R2Credential = { accessKeyId: string; secretAccessKey: string };
export type R2Response = { statusCode: number; body: Uint8Array };
export type R2Sender = (options: RequestOptions, body: Uint8Array | undefined, maximumResponseBytes: number) => Promise<R2Response>;
const directAgent = new Agent({ keepAlive: false, proxyEnv: { NODE_ENV: "production" } });

function hex(data: Uint8Array | string): string { return createHash("sha256").update(data).digest("hex"); }
function hmac(key: Uint8Array | string, data: string): Buffer { return createHmac("sha256", key).update(data).digest(); }
function valid(target: R2Target, credential: R2Credential, key: string): void {
  if (!/^[a-f0-9]{32}$/u.test(target.accountId) || /^0{32}$/u.test(target.accountId) ||
      !/^[a-z0-9-]{3,63}$/u.test(target.bucket) || !/^[A-Za-z0-9/_.-]{1,160}$/u.test(key) ||
      key.includes("..") || !credential.accessKeyId || !credential.secretAccessKey ||
      credential.accessKeyId.length > 256 || credential.secretAccessKey.length > 256) throw new Error("invalid-r2-contract");
}

/** One path-style SigV4 request. Native HTTPS has no middleware retry or redirect following. */
export async function oneR2Request(method: "PUT" | "GET" | "DELETE", target: R2Target, credential: R2Credential,
  key: string, body?: Uint8Array, maximumResponseBytes = 8_192, now = new Date(), send: R2Sender = nativeSend): Promise<R2Response> {
  valid(target, credential, key);
  if (method === "PUT" ? !body : Boolean(body)) throw new Error("invalid-r2-method");
  const hostname = `${target.accountId}.r2.cloudflarestorage.com`;
  const path = `/${target.bucket}/${key.split("/").map(encodeURIComponent).join("/")}`;
  const stamp = now.toISOString().replace(/[-:]|\.\d{3}/gu, "").replace("Z", "Z");
  const date = stamp.slice(0, 8);
  const payloadHash = hex(body ?? new Uint8Array());
  const headers: Record<string, string> = { host: hostname, "x-amz-content-sha256": payloadHash, "x-amz-date": stamp };
  if (body) headers["content-length"] = String(body.byteLength);
  const signedNames = Object.keys(headers).sort();
  const canonicalHeaders = signedNames.map((name) => `${name}:${headers[name].trim()}\n`).join("");
  const canonical = `${method}\n${path}\n\n${canonicalHeaders}\n${signedNames.join(";")}\n${payloadHash}`;
  const scope = `${date}/auto/s3/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${stamp}\n${scope}\n${hex(canonical)}`;
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${credential.secretAccessKey}`, date), "auto"), "s3"), "aws4_request");
  headers.authorization = `AWS4-HMAC-SHA256 Credential=${credential.accessKeyId}/${scope}, SignedHeaders=${signedNames.join(";")}, Signature=${hmac(signingKey, stringToSign).toString("hex")}`;
  return send({ protocol: "https:", hostname, port: 443, path, method, headers, timeout: 10_000 }, body, maximumResponseBytes);
}

/** Direct TLS only. The explicit agent has no inherited proxy environment. */
export async function nativeSend(options: RequestOptions, body: Uint8Array | undefined, maximumResponseBytes: number): Promise<R2Response> {
  return new Promise<R2Response>((resolve, reject) => {
    const deadlineMs = options.timeout ?? 10_000;
    if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 10_000) { reject(new Error("r2-deadline-contract")); return; }
    let finished = false;
    const settle = (error: Error | null, value?: R2Response) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value!);
    };
    const req = request({ ...options, agent: directAgent }, (res) => {
      const chunks: Uint8Array[] = [];
      let length = 0;
      res.on("data", (chunk: Buffer) => {
        length += chunk.byteLength;
        if (length > maximumResponseBytes) { req.destroy(new Error("r2-response-size")); return; }
        chunks.push(chunk);
      });
      res.on("end", () => settle(null, { statusCode: res.statusCode ?? 0, body: Buffer.concat(chunks) }));
      res.on("error", () => settle(new Error("r2-response-error")));
      res.on("close", () => { if (!res.complete) settle(new Error("r2-response-closed")); });
    });
    const timer = setTimeout(() => req.destroy(new Error("r2-deadline")), deadlineMs);
    req.on("timeout", () => req.destroy(new Error("r2-timeout")));
    req.on("error", () => settle(new Error("r2-transport")));
    req.end(body);
  });
}
