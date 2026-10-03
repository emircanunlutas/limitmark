import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import {
  EVIDENCE_ROOT, EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState, resolveEvidenceDirectory, sha256Hex, verifyEvidenceDirectory,
  type EvidenceManifest,
} from "../lab/evidence/manifest";
import { EvidenceViolation, assertEvidenceSafe } from "../lab/evidence/redact";

const refused = (error: unknown) => error instanceof EvidenceViolation;

test("evidence refuses every credential, header, cookie, identity and request-body carrier key", () => {
  const keys = [
    "authorization", "Authorization", "proxy-authorization", "cookie", "set-cookie", "Cookie", "password", "dbPassword", "secret", "clientSecret", "apiKey", "api_key", "x-api-key",
    "token", "accessToken", "submissionToken", "bearer", "credentials", "privateKey", "requestBody", "body", "payload", "formPayload", "x-forwarded-for", "forwarded",
    "clientIp", "remoteAddress", "ip", "address", "headers", "host", "hostname", "origin", "url", "connectionString", "databaseUrl", "email", "userEmail",
  ];
  for (const key of keys) assert.throws(() => assertEvidenceSafe({ metrics: { [key]: "x" } }), refused, key);
});

test("evidence refuses secrets and identities hiding in values", () => {
  const values = [
    "Bearer abcdefghijklmnop", "bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijk.signature", "Basic dXNlcjpwYXNzd29yZA==", "postgres://lab_migrator:hunter2@127.0.0.1:5432/db",
    "https://user:pw@example.test/", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk", "-----BEGIN PRIVATE KEY-----", "AKIAABCDEFGHIJKLMNOP", "re_abcdefghijklmnopqrstuvwx",
    "session=abcdef123456", "__Host-session=abcdef123456", "203.0.113.7", "client 198.51.100.4 failed", "10.0.0.1", "2001:db8::1", "fe80::1", "someone@example.test",
    "a".repeat(64), "A1b2".repeat(12), "x".repeat(600),
  ];
  for (const value of values) assert.throws(() => assertEvidenceSafe({ note: value }), refused, value.slice(0, 40));
  assert.throws(() => assertEvidenceSafe({ metrics: { list: ["fine", "203.0.113.7"] } }), refused);
  assert.throws(() => assertEvidenceSafe({ metrics: { nested: { deeper: { value: undefined } } } }), refused);
  assert.throws(() => assertEvidenceSafe({ metrics: { fn: () => 1 } }), refused);
});

test("evidence accepts the aggregates it is meant to carry", () => {
  assert.doesNotThrow(() => assertEvidenceSafe({
    schemaVersion: 1, runId: "20261002T203758Z-connectivity-baseline-056e00", result: "PASS", startedAt: "2026-10-02T20:37:58.040Z",
    git: { gitSha: "d7d6a7a35b3a47866f99257ae7c3eb5039defa81", dirty: false },
    thresholds: { id: "local-loopback-v1", version: 1, sha256: "8".repeat(64) },
    environment: { kernelRelease: "6.18.40.1-microsoft-standard-WSL2", nodeVersion: "v22.22.0", os: "Ubuntu 24.04.1 LTS" },
    metrics: { p95: 6.67, outcomes: { ok: 55, timeout: 2 }, path: "/test-talep-et" }, target: { id: "local-app", class: "lab-local", scheme: "http", port: 3000 },
  }));
});

test("environment versions that look like dotted quads are tolerated only inside `environment`", () => {
  assert.doesNotThrow(() => assertEvidenceSafe({ environment: { kernelRelease: "5.15.153.1-microsoft-standard-WSL2" } }));
  assert.throws(() => assertEvidenceSafe({ metrics: { kernelRelease: "5.15.153.1-microsoft-standard-WSL2" } }), refused);
  assert.throws(() => assertEvidenceSafe({ environment: { note: "Bearer abcdefghijklmnop" } }), refused);
  assert.throws(() => assertEvidenceSafe({ environment: { gitSha: "a".repeat(64) } }), refused);
});

test("the writer records the required fields, hashes every artifact and refuses unsafe content before touching disk", () => {
  const run = new EvidenceRun("unit-test", "evidence-test");
  try {
    assert.ok(run.directory.startsWith(path.join(REPOSITORY_ROOT, "artifacts", "lab")));
    assert.throws(() => run.addJsonArtifact("leak.json", { headers: { cookie: "a=b" } }), refused);
    assert.equal(existsSync(path.join(run.directory, "leak.json")), false, "a refused artifact must not reach disk");
    assert.throws(() => run.addJsonArtifact("../escape.json", {}), /plain \.json/);
    run.addJsonArtifact("phases.json", { phases: [{ name: "baseline", attempted: 3 }] });
    const manifest: EvidenceManifest = run.finalize({
      git: collectGitState(), environment: collectEnvironment("16.15"), target: { id: "local-app", class: "lab-local", scheme: "http", port: 3000 },
      workload: { id: "burst", phases: [{ name: "burst" }] }, ceilings: { hard: { maxConcurrency: 50 } },
      thresholds: { id: "local-loopback-v1", version: 1, sha256: "1".repeat(64) }, engine: "node-http", result: "PASS", resultReasons: [], metrics: { attempted: 3 },
    });
    for (const field of ["gitSha", "dirty"]) assert.ok(field in manifest.git);
    for (const field of ["os", "kernelRelease", "nodeVersion", "dockerVersion", "postgresVersion"]) assert.ok(field in manifest.environment, field);
    assert.equal(manifest.environment.postgresVersion, "16.15");
    assert.match(manifest.git.gitSha, /^[0-9a-f]{40}$/);
    assert.equal(manifest.target?.id, "local-app");
    assert.equal(manifest.thresholds?.id, "local-loopback-v1");
    assert.ok(manifest.startedAt <= manifest.endedAt);
    assert.equal(manifest.artifacts[0].sha256, sha256Hex(readFileSync(path.join(run.directory, "phases.json"))));
    assert.deepEqual(verifyEvidenceDirectory(run.directory), []);
    // Tampering is detected.
    writeFileSync(path.join(run.directory, "phases.json"), "{}\n");
    assert.deepEqual(verifyEvidenceDirectory(run.directory), ["phases.json"]);
    writeFileSync(path.join(run.directory, "manifest.json"), "{}\n");
    assert.deepEqual(verifyEvidenceDirectory(run.directory).sort(), ["manifest.json", "phases.json"]);
    assert.throws(() => run.finalize({} as never), /already finalized/);
  } finally { rmSync(run.directory, { recursive: true, force: true }); }
});

test("the manifest writer refuses a manifest that carries unsafe metrics", () => {
  const run = new EvidenceRun("unit-test", "evidence-refusal");
  try {
    assert.throws(() => run.finalize({
      git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: null, engine: "x",
      result: "ERROR", resultReasons: ["Bearer abcdefghijklmnop"], metrics: {},
    }), refused);
    assert.equal(existsSync(path.join(run.directory, "manifest.json")), false);
  } finally { rmSync(run.directory, { recursive: true, force: true }); }
});

test("evidence can only be written under the gitignored artifacts/lab tree", () => {
  for (const id of ["../../src", "..", "/etc", "a/b", "", "x", "run id with spaces", "C:\\temp"]) assert.throws(() => resolveEvidenceDirectory(id), /plain run id/, id);
  assert.throws(() => resolveEvidenceDirectory("20261002T203758Z-ok-run", path.join(REPOSITORY_ROOT, "src")), /plain run id/);
  assert.ok(resolveEvidenceDirectory("20261002T203758Z-ok-run").startsWith(EVIDENCE_ROOT));
  for (const probe of ["artifacts/lab/evidence/some-run/manifest.json", "artifacts/lab/pg/pg16.json", "artifacts/lab/targets.json", "artifacts/lab/k6/run/plan.json", "artifacts/lab/logs/x.log"]) {
    // `git check-ignore -q` exits 0 only when the path is ignored.
    assert.doesNotThrow(() => execFileSync("git", ["check-ignore", "-q", probe], { cwd: REPOSITORY_ROOT, stdio: "ignore" }), `${probe} must be gitignored`);
  }
});

test("credentials embedded in a URL are refused even without an IP address or e-mail shape", () => {
  for (const value of ["postgres://u:hunter2@db-host/app", "https://svc:pw12345@internal/x", "redis://default:abcdef@cache:6379"]) {
    assert.throws(() => assertEvidenceSafe({ note: value }), refused, value);
  }
});

// ---------------------------------------------------------------------------------------------- Codex F4 regressions
import { evidenceSafeError, findViolation, sanitizeLog, verifyLogText } from "../lab/evidence/redact";
import { writeSanitizedLog } from "../lab/evidence/manifest";

test("F4 regression: credentials in URL query strings are refused, whatever the parameter is called", () => {
  const values = [
    "https://example.test/cb?access_token=abc123def456", "/path?token=abc", "/path?api_key=zzz&x=1", "?sig=deadbeef", "a=1&b=2&c=3", "/x?code=1234&state=ab",
    "http://127.0.0.1:3000/?session=abc", "https://example.test/", "ws://example.test/socket", "file:///etc/passwd", "ftp://host/file", "https://x.test/p?q=1#frag",
  ];
  for (const value of values) assert.throws(() => assertEvidenceSafe({ note: value }), refused, value);
  // Nested and listed too.
  assert.throws(() => assertEvidenceSafe({ metrics: { deep: { list: ["fine", "https://example.test/?k=v"] } } }), refused);
});

test("F4 regression: cookies are refused generically (any name, any shape), not only a few well-known names", () => {
  const values = [
    "sid=abcdef123456", "JSESSIONID=ABC123XYZ", "connect.sid=s%3Aabcdef", "theme=dark; lang=tr", "__Secure-3PSID=abc", "id=1; Path=/; HttpOnly", "a=b", "x-token=whatever1", "_ga=GA1.2.123456",
    "Cookie: foo=bar", "cookie: foo=bar", "Set-Cookie: whatever=value; Secure", "Authorization: Basic Zm9vOmJhcg==", "authorization:Token abc",
    "last seen sid=abc123 at the edge", "k=v;k2=v2",
  ];
  for (const value of values) assert.throws(() => assertEvidenceSafe({ note: value }), refused, value);
});

test("F4 regression: IPv4 and IPv6 are refused, including IPv6 glued to a timestamp (the old prefix exemption let it through)", () => {
  const values = [
    "10.1.2.3", "client 203.0.113.9 reset", "::1", "2001:db8::1", "fe80::1", "fe80::1%eth0", "::ffff:192.0.2.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    // The reproduced bypass: anything after an ISO timestamp was exempt from the IPv6 scan.
    "2026-10-03T13:00:00Z 2001:db8::1", "2026-10-03T13:00:00.123Z fe80::1", "2026-10-03T13:00:00+03:00 client ::1", "2026-10-03T13:00:00Z2001:db8::1", "2026-10-03T13:00:00::1",
    "12:30:45 2001:db8::1", "at 12:30:45.123 from fe80::abcd", "2001:db8:10:20::1",
    "1:2:3:4:5:6:7:8", "12:34:56:78:9a:bc:de:f0",
  ];
  for (const value of values) assert.throws(() => assertEvidenceSafe({ note: value }), refused, value);
  // Legitimate timestamps and clock times stay accepted.
  for (const value of ["2026-10-03T13:00:00.000Z", "2026-10-03T13:00:00+03:00", "started 12:30:45 ended 12:31:00", "2026-10-03T13:00:00Z to 2026-10-03T13:05:00Z"]) {
    assert.doesNotThrow(() => assertEvidenceSafe({ note: value }), value);
  }
});

test("F4 regression: object KEYS are scanned like values (an address, token, URL, path or free text cannot hide in a key)", () => {
  const keys = [
    "203.0.113.7", "10.0.0.1:3000", "2001:db8::1", "Bearer abcdef123", "https://example.test/", "user@example.test", "/home/user/secret", "C:\\Users\\Emir\\x", "a b", "a;b", "x=1",
    "a".repeat(64), "A1b2".repeat(12), "k".repeat(65), "", "?token=abc", "line\nbreak", "ünicode-key",
  ];
  for (const key of keys) assert.throws(() => assertEvidenceSafe({ metrics: { [key]: 1 } }), refused, JSON.stringify(key));
  assert.throws(() => assertEvidenceSafe({ metrics: { nested: { "203.0.113.7": 1 } } }), refused);
  assert.throws(() => assertEvidenceSafe({ environment: { "203.0.113.7": 1 } }), refused);
  // Real labels (outcome categories, error codes, HTTP statuses, camelCase metrics) are fine.
  assert.doesNotThrow(() => assertEvidenceSafe({ metrics: { outcomes: { ECONNREFUSED: 1, "57P01": 2, conn_refused: 3, "200": 5, http_5xx: 1 }, totalAttempted: 3 } }));
});

test("F4 regression: stack traces, filesystem paths and error carriers are refused", () => {
  const values = [
    "Error: boom\n    at foo (C:\\Users\\Emir\\project\\a.ts:1:1)", "TypeError: x\n    at Object.<anonymous> (/home/runner/work/a.js:1:1)", "at async run (node:internal/modules/run_main:1:1)",
    "C:\\Users\\Emir\\Desktop\\x", "/home/user/.ssh/id_rsa", "/Users/someone/code", "/etc/passwd", "/var/lib/postgresql/data", "/tmp/x",
  ];
  for (const value of values) assert.throws(() => assertEvidenceSafe({ note: value }), refused, value.slice(0, 40));
  // The shape of evidence the runners really write for a failed run (an error rendered by evidenceSafeError) is accepted.
  assert.doesNotThrow(() => assertEvidenceSafe({ resultReasons: [evidenceSafeError(Object.assign(new Error("connect failed"), { code: "ECONNREFUSED" }))] }));
});

test("F4: evidenceSafeError keeps the class, the code and a safe message, and withholds anything else (never the stack)", () => {
  assert.equal(evidenceSafeError(Object.assign(new Error("connect failed"), { code: "ECONNREFUSED" })), "Error ECONNREFUSED: connect failed");
  assert.equal(evidenceSafeError(new TypeError("bad input")), "TypeError: bad input");
  for (const message of [
    "connect ECONNREFUSED 127.0.0.1:5432", "failed for https://example.test/?token=abc", "password=hunter22 rejected", "cannot open C:\\Users\\Emir\\x", "x".repeat(300), "line1\nline2",
    "Bearer abcdefghijklmnop", "postgres://lab_migrator:hunter2@127.0.0.1:5432/db", "a".repeat(40), "ünïcode",
  ]) {
    const rendered = evidenceSafeError(new Error(message));
    assert.equal(rendered, "Error: message withheld (not evidence-safe)", message.slice(0, 30));
    assert.doesNotThrow(() => assertEvidenceSafe({ note: rendered }));
  }
  const withStack = new Error("boom");
  withStack.stack = "Error: boom\n    at Object.<anonymous> (C:\\Users\\Emir\\a.ts:1:1)";
  assert.doesNotMatch(evidenceSafeError(withStack), /Users|\bat\b/);
  assert.equal(evidenceSafeError("a string"), "NonError");
  assert.equal(evidenceSafeError(null), "NonError");
  assert.doesNotThrow(() => assertEvidenceSafe({ r: evidenceSafeError(Object.assign(new Error("x"), { name: "Weird Name!!", code: "not a code" })) }));
});

test("F4 regression: raw child-process / parity output is never persisted verbatim", () => {
  const raw = [
    "ok  typecheck", "> next typegen && tsc --noEmit", "Authorization: Bearer abcdefghijklmnop", "connecting to postgres://lab_migrator:hunter2@127.0.0.1:5432/limitmark_lab_pg16",
    "Set-Cookie: sid=abcdef123456; HttpOnly", "client 203.0.113.9 reset the connection", "peer 2001:db8::1 gone", "GET /cb?access_token=zzz 200", "mail someone@example.test", "token sk-abcdefghijklmnopqrstuvwxyz",
    "    at Object.<anonymous> (C:\\Users\\Emir\\Desktop\\pentest-website\\a.ts:1:1)", "sha512-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf==", "\u001b[32mgreen line\u001b[0m", "plain line 42",
  ].join("\r\n");
  const result = sanitizeLog(raw);
  for (const secret of ["abcdefghijklmnop", "hunter2", "sid=abcdef", "203.0.113.9", "2001:db8::1", "access_token", "someone@example.test", "sk-abcdefghij", "Users\\Emir", "AbCdEfGhIjKl"]) {
    assert.ok(!result.text.includes(secret), `${secret} survived the sanitizer`);
  }
  assert.match(result.text, /ok {2}typecheck/);
  assert.match(result.text, /plain line 42/);
  assert.match(result.text, /green line/);
  assert.doesNotMatch(result.text, /\u001b/);
  assert.match(result.text, /<home>/, "the stack frame survives with its home directory rewritten");
  assert.ok(result.withheldLines >= 8, `withheld ${result.withheldLines}`);
  assert.ok(Object.keys(result.rules).length >= 5);
  // Every line of the sanitized output is itself acceptable evidence text apart from the ordinary-diagnostic rules it keeps.
  for (const line of result.text.split("\n")) assert.equal(findViolation(line.replace(/^\s+at\s+.*$/, "")), null, line);
});

test("F4: writeSanitizedLog persists only the sanitized text, under a plain .log name", () => {
  const directory = path.join(REPOSITORY_ROOT, "artifacts", "lab", "logs-test");
  try {
    const summary = writeSanitizedLog(directory, "case.log", "fine\npostgres://u:hunter2@h/db\nTOKEN=abcd1234\n");
    const written = readFileSync(path.join(directory, "case.log"), "utf8");
    assert.doesNotMatch(written, /hunter2|abcd1234/);
    assert.match(written, /\[line withheld: url-with-credentials\]/);
    assert.equal(summary.withheldLines, 2);
    for (const name of ["../x.log", "x.txt", "a/b.log", "", ".log", "x y.log"]) assert.throws(() => writeSanitizedLog(directory, name, "x"), /plain \.log/, name);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("F4: the parity runner persists child output only through the sanitizer, and no runner writes a raw error message", () => {
  const root = path.join(__dirname, "..", "lab");
  const parity = readFileSync(path.join(root, "linux", "parity.ts"), "utf8");
  assert.match(parity, /writeSanitizedLog\(/);
  assert.doesNotMatch(parity, /writeFileSync\(path\.join\(logDirectory/);
  for (const file of ["run.ts", "concurrency/harness.ts", "postgres/run-db-tests.ts", "postgres/guard-selftest.ts", "linux/parity.ts"]) {
    const source = readFileSync(path.join(root, file), "utf8");
    assert.doesNotMatch(source, /\.message\.slice\(/, `${file} persists a raw error message`);
  }
});

test("F4 (probe findings): cookie pairs after quotes/parentheses, labelled secrets, percent-escapes, numeric IPv4 and non-ASCII look-alikes are refused", () => {
  const values = [
    '{"a":"sid=abc123def"}', "(session=xyz)", "[JSESSIONID=ABCDEF]", "'k=v1234'", "SID = abc123", "sid:abc123", "password: hunter2", "token: abcdef123456", "api_key: zzzzzzzz", "secret = hunter2hunter2",
    "%73id=abc123", "a%20b", "3405803783", "0xCB007107", "\uff12\uff10\uff13.\uff10.\uff11\uff11\uff13.\uff17", "203.0.113.7".split("").join("\u200b"), "203\u30020\u3002113\u30027", "2001\uff1adb8\uff1a\uff1a1", "s\u200bid=abc123", "caf\u00e9", "tab\there is ok but nul\u0000 is not",
  ];
  for (const value of values) assert.throws(() => assertEvidenceSafe({ note: value }), refused, JSON.stringify(value));
});

test("F4 (parity finding): every ownership code the runners write is accepted evidence, and an over-long descriptive label is not (it broke the first parity app step)", () => {
  for (const ownership of ["lab-process", "lab-container-port", "lab-container-netns", "operator-asserted", "unproven"]) {
    assert.doesNotThrow(() => assertEvidenceSafe({ target: { id: "local-app", class: "lab-local", scheme: "http", port: 3000, ownership } }), ownership);
  }
  assert.throws(() => assertEvidenceSafe({ target: { ownership: "lab-labelled-container-publishing-the-port" } }), refused);
  const source = readFileSync(path.join(__dirname, "..", "lab", "run.ts"), "utf8");
  for (const match of source.matchAll(/ownership = "([^"]+)"/g)) assert.ok(match[1].length < 32, match[1]);
});

test("F4: log sanitising keeps stack frames readable (positions neutralized) while still withholding real addresses", () => {
  const kept = sanitizeLog("location: '/app/tests/x.test.ts:299:1'\n    at Test.run (node:internal/test_runner/test:1047:25)\nerror at src/a.ts:12:34\npeer 2001:db8::1 gone\n");
  assert.match(kept.text, /x\.test\.ts:L:C/);
  assert.match(kept.text, /at Test\.run \(node:internal\/test_runner\/test:L:C\)/);
  assert.match(kept.text, /src\/a\.ts:L:C/);
  assert.ok(!kept.text.includes("2001:db8::1"));
  assert.equal(kept.withheldLines, 1);
});

/** Round 2: payloads that leaked through the first sanitizer (stack-shaped lines were blanked before scanning, and an exempt rule masked every later one). */
const LOG_LEAKS: [string, string][] = [
  ["stack frame with a URL query credential", "    at fetchIt (https://svc.example.test/cb?access_token=SECRETQ123:12:5)"],
  ["stack frame with a file URL query credential", "    at run (file:///app/lab/x.ts?token=SECRETQ456:3:9)"],
  ["stack frame with a generic cookie", "    at handler (/app/src/h.ts:1:2) sid=SECRETC789; theme=dark"],
  ["stack frame with a Cookie header", "    at send (/app/x.ts:1:2) Cookie: session=SECRETC790"],
  ["stack frame with a Bearer credential", "    at call (/app/x.ts:1:2) Authorization: Bearer SECRETB123abc"],
  ["bare Bearer in a stack frame", "    at call (/app/x.ts:1:2) Bearer SECRETB124abcdef"],
  ["stack frame with IPv6", "    at connect (/app/x.ts:1:2) peer 2001:db8::5eed"],
  ["path line with IPv6 (exempt rule must not mask it)", "cannot open /home/runner/work/a.ts from fe80::5eed"],
  ["timestamp-adjacent IPv6", "2026-10-03T13:00:00Z 2001:db8::7e57 refused"],
  ["timestamp glued to IPv6", "2026-10-03T13:00:00.123Z2001:db8::7e58"],
  ["clock time then IPv6", "at 12:30:45 from fe80::7e59"],
  ["numeric IPv6 (full form)", "peer 2001:0db8:0000:0000:0000:0000:7e60:0001 gone"],
  ["IPv4-mapped IPv6 in hex", "peer ::ffff:cb00:7e61 gone"],
  ["IPv4 in a stack frame", "    at dial (/app/x.ts:1:2) 203.0.113.62"],
  ["decimal IPv4", "peer 3405803839 gone"],
  ["percent-encoded cookie name", "    at x (/app/x.ts:1:2) %73id=SECRETP125"],
  ["full-width digits address", "peer \uff12\uff10\uff13.\uff10.\uff11\uff11\uff13.\uff17\uff16\uff13 gone"],
  ["zero-width split cookie", "s\u200bid=SECRETZ126"],
  ["labelled secret with colon", "    at login (/app/x.ts:1:2) password: SECRETL127"],
  ["e-mail in a stack frame", "    at mail (/app/x.ts:1:2) to someone.62@example.test"],
  ["connection URL with credentials", "    at connect (/app/x.ts:1:2) postgres://u:SECRETU128@db/app"],
  ["very long line with a secret after the truncation point", `${"a ".repeat(250)}Bearer SECRETT129abc`],
];

test("F4 round 2 regression: every log-leak payload is withheld, including stack-shaped lines, and the bytes that remain pass the final scanner", () => {
  for (const [name, payload] of LOG_LEAKS) {
    const result = sanitizeLog(`before\n${payload}\nafter\n`);
    assert.doesNotMatch(result.text, /SECRET|2001:db8|fe80::|203\.0\.113|3405803839|cb00|someone\.62|\uff12/, name);
    assert.match(result.text, /^before\n/, name);
    assert.match(result.text, /\nafter\n/, name);
    assert.ok(result.withheldLines >= 1 || result.text.includes("[truncated]"), name);
    assert.equal(verifyLogText(result.text), null, name);
  }
  // Everything at once, and idempotence: sanitizing sanitized output changes nothing.
  const all = LOG_LEAKS.map(([, payload]) => payload).join("\n");
  const once = sanitizeLog(all);
  assert.equal(sanitizeLog(once.text).text, once.text);
  assert.equal(verifyLogText(once.text), null);
});

test("F4 round 2: verifyLogText is the final gate: it rejects what a broken sanitizer would have let through, and writeSanitizedLog writes exactly the verified bytes", () => {
  for (const [, payload] of LOG_LEAKS) assert.notEqual(verifyLogText(`${payload}\n`), null, payload.slice(0, 40));
  assert.equal(verifyLogText("plain line\n    at Test.run (node:internal/test_runner/test:L:C)\n"), null);
  assert.notEqual(verifyLogText("x".repeat(600)), null);
  const directory = path.join(REPOSITORY_ROOT, "artifacts", "lab", "logs-test2");
  try {
    const raw = LOG_LEAKS.map(([, payload]) => payload).join("\n");
    const summary = writeSanitizedLog(directory, "leaks.log", raw);
    const onDisk = readFileSync(path.join(directory, "leaks.log"), "utf8");
    assert.equal(onDisk, summary.text, "the persisted bytes are the sanitized representation, not another one");
    assert.equal(verifyLogText(onDisk), null);
    assert.doesNotMatch(onDisk, /SECRET/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
  const source = readFileSync(path.join(__dirname, "..", "lab", "evidence", "manifest.ts"), "utf8");
  assert.ok(source.indexOf("verifyLogText(sanitized.text)") < source.indexOf("writeFileSync(path.join(directory, name), sanitized.text)"), "verify before write, on the same string");
});

test("F4 round 2 (property): random log lines carrying a secret in a random wrapper never keep the secret, and the output always verifies", () => {
  let seed = 31337;
  const rand = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };
  const pick = <T,>(items: readonly T[]) => items[Math.floor(rand() * items.length)];
  const secrets = ["sid=ZQXSECRET1", "Bearer ZQXSECRET2abc", "?token=ZQXSECRET3", "2001:db8::ZQ".replace("ZQ", "7ab"), "203.0.113.77", "Cookie: a=ZQXSECRET4", "password: ZQXSECRET5", "user@example.test", "ftp://h/p?k=ZQXSECRET6"];
  const wrappers = [(x: string) => x, (x: string) => `    at fn (/app/x.ts:1:2) ${x}`, (x: string) => `2026-10-03T13:00:00Z ${x}`, (x: string) => `(${x})`, (x: string) => `"${x}"`, (x: string) => `/home/u/a.ts ${x} /tmp/z`, (x: string) => `${"pad ".repeat(Math.floor(rand() * 30))}${x}`, (x: string) => `    at f (file:///app/y.ts:9:9) [${x}]`];
  for (let n = 0; n < 5_000; n++) {
    const secret = pick(secrets), line = pick(wrappers)(secret);
    const out = sanitizeLog(line);
    assert.doesNotMatch(out.text, /ZQXSECRET|2001:db8|203\.0\.113\.77|user@example/, JSON.stringify(line));
    assert.equal(verifyLogText(out.text), null, JSON.stringify(line));
  }
});

test("F4: the parity runner persists child output only through the sanitizer, and no runner writes a raw error message", () => {
  const root = path.join(__dirname, "..", "lab");
  const parity = readFileSync(path.join(root, "linux", "parity.ts"), "utf8");
  assert.match(parity, /writeSanitizedLog\(/);
  assert.doesNotMatch(parity, /writeFileSync\(path\.join\(logDirectory/);
  for (const file of ["run.ts", "concurrency/harness.ts", "postgres/run-db-tests.ts", "postgres/guard-selftest.ts", "linux/parity.ts"]) {
    const source = readFileSync(path.join(root, file), "utf8");
    assert.doesNotMatch(source, /\.message\.slice\(/, `${file} persists a raw error message`);
  }
});

test("F4 (probe findings): cookie pairs after quotes/parentheses, labelled secrets, percent-escapes, numeric IPv4 and non-ASCII look-alikes are refused", () => {
  const values = [
    '{"a":"sid=abc123def"}', "(session=xyz)", "[JSESSIONID=ABCDEF]", "'k=v1234'", "SID = abc123", "sid:abc123", "password: hunter2", "token: abcdef123456", "api_key: zzzzzzzz", "secret = hunter2hunter2",
    "%73id=abc123", "a%20b", "3405803783", "0xCB007107", "\uff12\uff10\uff13.\uff10.\uff11\uff11\uff13.\uff17", "203.0.113.7".split("").join("\u200b"), "203\u30020\u3002113\u30027", "2001\uff1adb8\uff1a\uff1a1", "s\u200bid=abc123", "caf\u00e9", "tab\there is ok but nul\u0000 is not",
  ];
  for (const value of values) assert.throws(() => assertEvidenceSafe({ note: value }), refused, JSON.stringify(value));
});

test("F4 (parity finding): every ownership code the runners write is accepted evidence, and an over-long descriptive label is not (it broke the first parity app step)", () => {
  for (const ownership of ["lab-process", "lab-container-port", "lab-container-netns", "operator-asserted", "unproven"]) {
    assert.doesNotThrow(() => assertEvidenceSafe({ target: { id: "local-app", class: "lab-local", scheme: "http", port: 3000, ownership } }), ownership);
  }
  assert.throws(() => assertEvidenceSafe({ target: { ownership: "lab-labelled-container-publishing-the-port" } }), refused);
  const source = readFileSync(path.join(__dirname, "..", "lab", "run.ts"), "utf8");
  for (const match of source.matchAll(/ownership = "([^"]+)"/g)) assert.ok(match[1].length < 32, match[1]);
});


test("F4 round 2: the token-like-key rule counts digits, not the letter d (/d/g bug)", () => {
  assert.doesNotThrow(() => assertEvidenceSafe({ metrics: { dddddddddddddddddddddddddd: 1, deadDeadDeadDeadDeadDeadDead: 2 } }));
  assert.throws(() => assertEvidenceSafe({ metrics: { abcdefghijkl1234mnopqrstuv: 1 } }), refused);
});
