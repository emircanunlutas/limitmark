/**
 * G1: the BUILT application's real `GET /test-talep-et` output must satisfy the Slice-3 enrollment structural contract
 * (defense/core/enrollment.ts) EXACTLY. Not part of `npm test`: it needs a production build.
 *
 *   npm run build
 *   npx tsx --conditions=react-server tests/built-form-enrollment.integration.ts
 *
 * It starts the lab-managed local application (`next start` of the existing build, scrubbed environment, loopback port, demo adapter),
 * fetches every reviewed form-route target and applies the same matcher the plane uses. If the real response does not satisfy the contract
 * the script FAILS with the exact mismatch: the matcher is never weakened to make it pass, and any change goes back to design review.
 */
import assert from "node:assert/strict";
import http from "node:http";
import { ENROLL_CONTENT_TYPE, FORM_ROUTE_TARGETS, evaluateObservation } from "../defense/core/enrollment";
import { LocalApp } from "../lab/host/local-app";

type Page = { status: number; rawHeaders: string[]; body: Buffer };

function get(port: number, target: string): Promise<Page> {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port, path: target, method: "GET", headers: { host: `127.0.0.1:${port}` }, agent: false }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, rawHeaders: response.rawHeaders, body: Buffer.concat(chunks) }));
    });
    request.on("error", reject);
    request.end();
  });
}

async function main(): Promise<void> {
  const app = new LocalApp(3100);
  await app.start();
  try {
    await app.waitUntilListening();
    for (const target of FORM_ROUTE_TARGETS) {
      const page = await get(3100, target);
      const verdict = evaluateObservation({ status: page.status, rawHeaders: page.rawHeaders, payload: page.body }, 1_048_576);
      assert.equal(verdict.ok, true, `G1 ${target}: ${verdict.ok ? "" : verdict.reason} (status ${page.status})`);
      const text = page.body.toString("latin1");
      assert.equal(page.status, 200, target);
      assert.equal((text.match(/name="submissionToken"/g) ?? []).length, 1, `${target}: exactly one literal token field`);
      assert.equal(page.rawHeaders.filter((value, index) => index % 2 === 0 && value.toLowerCase() === "content-type").length, 1, `${target}: exactly one Content-Type`);
      assert.equal(page.rawHeaders.some((value, index) => index % 2 === 0 && value.toLowerCase() === "content-encoding"), false, `${target}: no Content-Encoding`);
      assert.ok(page.rawHeaders.some((value, index) => index % 2 === 1 && value.toLowerCase() === ENROLL_CONTENT_TYPE), `${target}: exact content type`);
      assert.match(text, /<form class="request-form"/, `${target}: the reviewed form element`);
      console.log(`ok  ${target}: status ${page.status}, ${page.body.length} bytes, one reviewed token input inside the request form`);
    }
    console.log("G1 PASSED: the built application's real form output satisfies the enrollment contract");
  } finally {
    await app.kill();
  }
}

main().then(() => process.exit(0), (error) => { console.error(error instanceof Error ? error.message : "G1 FAILED"); process.exit(1); });
