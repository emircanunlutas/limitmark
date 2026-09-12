import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import http from "node:http";
import net from "node:net";
import { join } from "node:path";
import {
  INGRESS_BODY_ENCODING, INGRESS_ENVIRONMENT, INGRESS_HEADER, INGRESS_IDENTITY_VERSION,
  INGRESS_MUTATION_CONTENT_TYPE, INGRESS_MUTATION_PATH, INGRESS_VERSION,
  createIngressEnvelope, encodeBase64url, sha256Base64url, type IngressPayload,
} from "../src/lib/ingress-protocol";

const port = 3197;
const origin = `http://127.0.0.1:${port}`;
const processOutput = new WeakMap<ChildProcess, string[]>();

function start(): ChildProcess {
  const child = spawn(process.execPath, [join(process.cwd(), "node_modules/next/dist/bin/next"), "start", "--hostname", "127.0.0.1", "--port", String(port)], {
    cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
    env: { ...process.env, REQUEST_SUBMISSION_MODE: "demo", ALLOW_DEMO_SUBMISSIONS: "true", PUBLIC_DEMO_ORIGIN: origin },
  });
  const output: string[] = [];
  processOutput.set(child, output);
  child.stdout?.on("data", (chunk) => output.push(String(chunk)));
  child.stderr?.on("data", (chunk) => output.push(String(chunk)));
  return child;
}

async function waitForReady(child: ChildProcess): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error(`Next exited early: ${child.exitCode}\n${processOutput.get(child)?.join("") ?? ""}`);
    try { if ((await fetch(`${origin}/test-talep-et`)).ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("built Next server did not become ready");
}

async function stop(child: ChildProcess): Promise<void> {
  if (process.platform === "win32" && child.pid) {
    spawnSync("taskkill.exe", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
  } else if (child.exitCode === null) child.kill("SIGTERM");
  if (child.exitCode === null) {
    await new Promise<void>((resolve) => { child.once("exit", () => resolve()); setTimeout(resolve, 3_000); });
  }
  child.stdout?.destroy();
  child.stderr?.destroy();
}

type HttpResult = { status: number; headers: http.IncomingHttpHeaders; body: string };
function requestChunks(path: string, method: string, chunks: readonly Uint8Array[], headers: Record<string, string> = {}): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const request = http.request({ hostname: "127.0.0.1", port, path, method, agent: false, headers: {
      connection: "close", origin, "content-type": INGRESS_MUTATION_CONTENT_TYPE, ...headers,
    } }, (response) => {
      const body: Buffer[] = [];
      response.on("data", (chunk) => body.push(Buffer.from(chunk)));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(body).toString("utf8") }));
    });
    request.setTimeout(10_000, () => request.destroy(new Error("built route request timed out")));
    request.on("error", reject);
    for (const chunk of chunks) request.write(chunk);
    request.end();
  });
}

function prematureContentLength(body: Uint8Array): Promise<number | null> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const response: Buffer[] = [];
    socket.setTimeout(10_000, () => socket.destroy(new Error("truncated request timed out")));
    socket.on("data", (chunk) => response.push(Buffer.from(chunk)));
    socket.on("error", (error) => {
      if ((error as NodeJS.ErrnoException).code === "ECONNRESET") resolve(null);
      else reject(error);
    });
    socket.on("close", () => {
      const match = Buffer.concat(response).toString("latin1").match(/^HTTP\/1\.1 (\d{3})/u);
      resolve(match ? Number(match[1]) : null);
    });
    socket.on("connect", () => {
      socket.write(`POST ${INGRESS_MUTATION_PATH} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nOrigin: ${origin}\r\nContent-Type: ${INGRESS_MUTATION_CONTENT_TYPE}\r\nContent-Length: ${body.length + 10}\r\nConnection: close\r\n\r\n`);
      socket.end(body);
    });
  });
}

function exactPrefix(): string {
  const form = new URLSearchParams({ name: "Synthetic", email: "qa@example.test", service: "web", system: "Disposable",
    objective: "Review boundary", environment: "staging", authority: "authorized", protection: "unknown", provider: "",
    notes: "", submissionToken: "s".repeat(43) });
  const initial = form.toString();
  form.set("notes", "x".repeat(273 - initial.length));
  const result = form.toString();
  assert.equal(Buffer.byteLength(result), 273);
  return result;
}

async function signedPrefixHeader(body: Uint8Array): Promise<string> {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const payload: IngressPayload = [INGRESS_VERSION, "test-key", INGRESS_ENVIRONMENT, "prj_limitmark", "dpl_reviewed", Date.now(),
    "POST", "https", "limitmark.com", INGRESS_MUTATION_PATH, "", INGRESS_MUTATION_CONTENT_TYPE, INGRESS_BODY_ENCODING,
    body.length, await sha256Base64url(body), INGRESS_IDENTITY_VERSION, encodeBase64url(new Uint8Array(32).fill(1)), encodeBase64url(new Uint8Array(16).fill(2))];
  return createIngressEnvelope(payload, pair.privateKey);
}

async function main() {
  const server = start();
  try {
    await waitForReady(server);
    const prefix = new TextEncoder().encode(exactPrefix());
    const signedHeader = await signedPrefixHeader(prefix);
    const accepted = await requestChunks(INGRESS_MUTATION_PATH, "POST", [prefix], { [INGRESS_HEADER]: signedHeader });
    assert.equal(accepted.status, 200);
    assert.match(String(accepted.headers["cache-control"]), /no-store/u);

    const exact = await requestChunks(INGRESS_MUTATION_PATH, "POST", [new Uint8Array(32_768).fill(120)]);
    assert.equal(exact.status, 400);
    assert.match(String(exact.headers["cache-control"]), /no-store/u);
    for (const chunks of [
      [new Uint8Array(32_769).fill(120)],
      [new Uint8Array(1).fill(120), new Uint8Array(32_767).fill(120), new Uint8Array(1).fill(120)],
      [new Uint8Array(32_768).fill(120), new Uint8Array(1).fill(120)],
    ]) {
      const overflow = await requestChunks(INGRESS_MUTATION_PATH, "POST", chunks);
      assert.equal(overflow.status, 413);
      assert.match(String(overflow.headers["cache-control"]), /no-store/u);
    }

    // This is the adjudicated Next.js 16.3.4 reproduction: if Proxy discards
    // the threshold-crossing chunk, the signed 273-byte demo prefix returns 200.
    const discardedTail = await requestChunks(INGRESS_MUTATION_PATH, "POST", [prefix, new Uint8Array(65_536).fill(120)], { [INGRESS_HEADER]: signedHeader });
    assert.equal(discardedTail.status, 413);
    assert.notEqual(discardedTail.status, accepted.status);

    const truncatedStatus = await prematureContentLength(prefix);
    assert.notEqual(truncatedStatus, 200);
    for (const [method, path] of [["GET", INGRESS_MUTATION_PATH], ["PUT", INGRESS_MUTATION_PATH], ["POST", `${INGRESS_MUTATION_PATH}/`],
      ["POST", "/api//public-inquiries"], ["POST", "/api/%70ublic-inquiries"]] as const) {
      const alternate = await requestChunks(path, method, method === "POST" ? [prefix] : []);
      assert.notEqual(alternate.status, 200);
      if (path === INGRESS_MUTATION_PATH) assert.match(String(alternate.headers["cache-control"]), /no-store/u);
    }
  } finally {
    await stop(server);
  }
  console.log("Built Next route body boundary: PASS (chunked overflow tail remained visible to the authoritative reader)");
}

void main().then(
  () => process.exit(0),
  (error: unknown) => { console.error(error); process.exit(1); },
);
