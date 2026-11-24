import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import ts from "typescript";
import { BOUND_HEADER_NAMES, REFUSED_HEADERS, SEMANTIC_POLICY_VERSION, classifyHeader } from "../defense/core/semantic-request";
import { OB_REASONS } from "../defense/core/types";
import { DIRECT_CORPUS_FIXED_COUNT, DIRECT_ENTRIES, DIRECT_POSITIVE_CONTROLS, DIRECT_SCENARIOS } from "../lab/defense/direct-corpus";
import { SEMANTIC_CORPUS, SEMANTIC_CORPUS_FIXED_COUNT, SEMANTIC_EXPECTED_DROPPED } from "../lab/defense/semantic-corpus";

const root = path.join(__dirname, "..");
const read = (relative: string) => readFileSync(path.join(root, relative), "utf8");
function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? sourceFiles(full) : /\.(ts|tsx)$/.test(entry.name) ? [full] : [];
  });
}

/**
 * Header literals read by the given source files, plus the reads PROVEN to be outbound.
 *
 * The scan stays lexical and unchanged for every read EXCEPT one class: a `<x>.headers.get("literal")` whose receiver the TYPE
 * CHECKER proves is a fetch `Response` (the library type, not a project type) held in a `const` that is initialised by
 * `await <call>` with no assertion in between. That is "interpretation of a provider response", not of an inbound request. The
 * proof is semantic, so it cannot be transferred by choosing a variable name, a file, a header name or a position: an inbound
 * `Request`, a cast, a parameter, an annotated or `any` value, optional chaining, `has()` and bracket access all fail it and
 * are reported exactly as before.
 */
type HeaderScan = { found: Map<string, string[]>; outbound: Array<{ file: string; header: string }> };

const blankComments = (text: string) => text
  .replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, " "))
  .replace(/(^|[^:"'`])\/\/.*$/gm, (line, lead: string) => lead + " ".repeat(line.length - lead.length));

function isLibraryResponse(checker: ts.TypeChecker, program: ts.Program, node: ts.Expression): boolean {
  const type = checker.getTypeAtLocation(node);
  const symbol = type.getSymbol();
  if (!symbol || symbol.getName() !== "Response" || (type.flags & ts.TypeFlags.Any) !== 0) return false;
  const declarations = symbol.getDeclarations() ?? [];
  return declarations.length > 0 && declarations.every((declaration) => {
    const source = declaration.getSourceFile();
    return program.isSourceFileDefaultLibrary(source) || /[\\/]node_modules[\\/]/.test(source.fileName);
  });
}

/** True only for `const x = await <call>` (no annotation, no assertion, not optional) whose `x.headers.get(literal)` this is. */
function isProvenOutboundRead(checker: ts.TypeChecker, program: ts.Program, call: ts.CallExpression): boolean {
  const access = call.expression;
  if (!ts.isPropertyAccessExpression(access) || access.name.text !== "get" || access.questionDotToken) return false;
  const headers = access.expression;
  if (!ts.isPropertyAccessExpression(headers) || headers.name.text !== "headers" || headers.questionDotToken) return false;
  const receiver = headers.expression;
  if (!ts.isIdentifier(receiver)) return false;
  const declaration = checker.getSymbolAtLocation(receiver)?.valueDeclaration;
  if (!declaration || !ts.isVariableDeclaration(declaration) || declaration.type || declaration.exclamationToken) return false;
  if (!ts.isVariableDeclarationList(declaration.parent) || !(declaration.parent.flags & ts.NodeFlags.Const)) return false;
  const initializer = declaration.initializer;
  if (!initializer || !ts.isAwaitExpression(initializer)) return false;
  const operand = initializer.expression;
  if (!ts.isCallExpression(operand)) return false;
  if ((checker.getTypeAtLocation(operand).flags & ts.TypeFlags.Any) !== 0) return false;
  return isLibraryResponse(checker, program, receiver);
}

export function scanHeaderReads(files: ReadonlyArray<{ name: string; text: string }>, program: ts.Program): HeaderScan {
  const found = new Map<string, string[]>();
  const outbound: HeaderScan["outbound"] = [];
  const checker = program.getTypeChecker();
  const note = (name: string, file: string) => found.set(name, [...(found.get(name) ?? []), file]);
  for (const { name: file, text: original } of files) {
    const text = original.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
    const source = program.getSourceFile(file);
    const proven = new Set<number>();
    if (source) {
      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node) && isProvenOutboundRead(checker, program, node)) proven.add((node.expression as ts.PropertyAccessExpression).name.getStart(source));
        ts.forEachChild(node, visit);
      };
      visit(source);
    }
    for (const match of blankComments(original).matchAll(/headers\.(?:get|has)\(\s*["']([A-Za-z0-9-]+)["']/g)) {
      const header = match[1].toLowerCase();
      if (proven.has(match.index + "headers.".length)) outbound.push({ file, header });
      else note(header, file);
    }
    for (const match of text.matchAll(/headers\[\s*["']([A-Za-z0-9-]+)["']\s*\]/g)) note(match[1].toLowerCase(), file);
    for (const match of text.matchAll(/\[((?:\s*"[A-Za-z0-9-]+",?)+)\s*\]\s*\.some\(\(name\) => headers\.get\(name\)/g)) for (const name of match[1].matchAll(/"([A-Za-z0-9-]+)"/g)) note(name[1].toLowerCase(), file);
    // public-origin.ts exports the name of its secret header as a constant that is then read through headers.get(constant)
    for (const match of text.matchAll(/export const \w*[Hh]eader = "([a-z0-9-]+)"/g)) note(match[1].toLowerCase(), file);
  }
  return { found, outbound };
}

function sourceProgram(files: string[]): ts.Program {
  const configPath = path.join(root, "tsconfig.json");
  const config = ts.readConfigFile(configPath, (file) => readFileSync(file, "utf8"));
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
  return ts.createProgram(files, { ...parsed.options, noEmit: true, incremental: false, tsBuildInfoFile: undefined, plugins: undefined });
}

let realScan: HeaderScan | null = null;
function headersReadBySrc(): Map<string, string[]> {
  realScan ??= (() => {
    const files = sourceFiles(path.join(root, "src")).sort();
    const scan = scanHeaderReads(files.map((file) => ({ name: file, text: readFileSync(file, "utf8") })), sourceProgram(files));
    const relative = (file: string) => path.relative(root, file).replace(/\\/g, "/");
    return {
      found: new Map([...scan.found].map(([name, list]) => [name, list.map(relative)])),
      outbound: scan.outbound.map((read) => ({ ...read, file: relative(read.file) })),
    };
  })();
  return realScan.found;
}

test("CONTRACT: every header the real application reads is bound, derived, transport, refused, spoofable or an ingress indicator: never silently dropped", () => {
  const reads = headersReadBySrc();
  assert.ok(reads.size >= 10, `the scan must actually see the application's header reads (saw ${[...reads.keys()].join(", ")})`);
  for (const expected of ["host", "origin", "content-type", "content-length", "content-encoding", "x-forwarded-host", "x-limitmark-origin-secret", "x-vercel-forwarded-for", "authorization", "cf-connecting-ip", "cf-ray"]) {
    assert.ok(reads.has(expected), `the scan found ${expected}`);
  }
  const dropped = [...reads.keys()].filter((name) => classifyHeader(name) === "dropped");
  assert.deepEqual(dropped, [], `the application started interpreting a header the plane drops: bump SEMANTIC_POLICY_VERSION and bind or refuse it (${dropped.join(", ")})`);
});


/** In-memory project: the virtual files plus the real compiler libraries, so `Request`/`Response`/`fetch` resolve to the library types. */
function virtualProgram(sources: Record<string, string>): { program: ts.Program; files: Array<{ name: string; text: string }> } {
  const options: ts.CompilerOptions = { target: ts.ScriptTarget.ES2022, lib: ["lib.dom.d.ts", "lib.esnext.d.ts"], strict: true, noEmit: true, types: [], skipLibCheck: true, module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler };
  const host = ts.createCompilerHost(options);
  const virtual = new Map(Object.entries(sources).map(([name, text]) => [path.join(root, "virtual", name).replace(/\\/g, "/"), text]));
  const originalGet = host.getSourceFile.bind(host);
  host.getSourceFile = (name, languageVersion, ...rest) => virtual.has(name) ? ts.createSourceFile(name, virtual.get(name)!, languageVersion, true) : originalGet(name, languageVersion, ...rest);
  host.fileExists = ((original) => (name: string) => virtual.has(name) || original(name))(host.fileExists.bind(host));
  host.readFile = ((original) => (name: string) => virtual.get(name) ?? original(name))(host.readFile.bind(host));
  const names = [...virtual.keys()];
  return { program: ts.createProgram(names, options, host), files: names.map((name) => ({ name, text: virtual.get(name)! })) };
}

const virtualScan = (sources: Record<string, string>) => {
  const { program, files } = virtualProgram(sources);
  const scan = scanHeaderReads(files, program);
  return { found: [...scan.found.keys()].sort(), outbound: scan.outbound.map((read) => read.header) };
};

test("CONTRACT: the one proven outbound provider-response read is the only read the scan does not count as inbound", () => {
  headersReadBySrc();
  assert.deepEqual(realScan?.outbound, [{ file: "src/lib/resend-notification-adapter.ts", header: "retry-after" }], "adding another outbound read is a reviewed change to this list");
  assert.equal(headersReadBySrc().has("retry-after"), false, "it is not an inbound header");
  assert.equal(SEMANTIC_POLICY_VERSION, 1);
  assert.equal(classifyHeader("retry-after"), "dropped", "the plane policy is unchanged: an inbound retry-after is still dropped");
});

test("CONTRACT: the outbound privilege is a type proof; an inbound Request cannot obtain it, even under identical names", () => {
  const provider = 'export async function send(fetchImplementation: (u: string) => Promise<Response>) { const response = await fetchImplementation("x"); return response.headers.get("retry-after"); }';
  assert.deepEqual(virtualScan({ "a.ts": provider }), { found: [], outbound: ["retry-after"] }, "the provider-response read is accepted");
  const inbound: Record<string, string> = {
    "same-names": 'export async function handle(request: Request) { const response = request; return response.headers.get("retry-after"); }',
    "same-names-await": 'export async function handle(request: Request) { const response = await Promise.resolve(request); return response.headers.get("retry-after"); }',
    "request-param": 'export function handle(request: Request) { return request.headers.get("retry-after"); }',
    "response-param": "export function f(response: Response) { return response.headers.get(\"retry-after\"); }",
    "annotated": 'export async function f(request: Request) { const response: Response = await (request as never); return response.headers.get("retry-after"); }',
    "cast-through-call": 'declare function id(value: unknown): any; export async function f(request: Request) { const response = await id(request); return response.headers.get("retry-after"); }',
    "assertion": 'export async function f(request: Request) { const response = await (request as unknown as Promise<Response>); return response.headers.get("retry-after"); }',
    "let-binding": 'export async function f(g: () => Promise<Response>) { let response = await g(); return response.headers.get("retry-after"); }',
    "optional": 'export async function f(g: () => Promise<Response | null>) { const response = await g(); return response?.headers.get("retry-after"); }',
    "has": 'export async function f(g: () => Promise<Response>) { const response = await g(); return response.headers.has("retry-after"); }',
    "bracket": 'export async function f(g: () => Promise<Response>) { const response = await g(); return (response as never as { headers: Record<string, string> }).headers["retry-after"]; }',
    "project-type": 'type Response = { headers: Headers }; export async function f(request: Request, g: () => Promise<Response>) { const response = await g(); return response.headers.get("retry-after"); }',
    "bare-headers": 'export function f(request: Request) { const headers = request.headers; return headers.get("retry-after"); }',
  };
  for (const [name, source] of Object.entries(inbound)) {
    assert.deepEqual(virtualScan({ [name + ".ts"]: source }), { found: ["retry-after"], outbound: [] }, name);
  }
  // one file, one provider read plus an unrelated inbound read of the same header name: only the provider read is outbound
  assert.deepEqual(virtualScan({ "mixed.ts": provider + ' export function handle(request: Request) { return request.headers.get("retry-after"); }' }), { found: ["retry-after"], outbound: ["retry-after"] });
});

test("CONTRACT: the bound set is exactly what the application's public path interprets, and the policy is versioned", () => {
  assert.deepEqual([...BOUND_HEADER_NAMES], ["content-type", "host", "origin"]);
  assert.equal(SEMANTIC_POLICY_VERSION, 1);
  const handler = read("src/lib/public-inquiry-handler.server.ts");
  assert.match(handler, /headers\.get\("content-type"\)/);
  assert.match(handler, /headers\.get\("origin"\)/);
  assert.match(handler, /headers\.get\("content-encoding"\)/);
  assert.ok(REFUSED_HEADERS.has("content-encoding"), "content-encoding is read by the application and refused, not dropped");
  assert.ok(REFUSED_HEADERS.has("authorization"));
  // headers the application does NOT read anywhere in src/ are exactly the ones the policy may drop
  const reads = headersReadBySrc();
  for (const name of ["accept", "user-agent", "cookie", "referer", "accept-language", "cache-control", "if-none-match"]) {
    assert.equal(reads.has(name), false, `${name} is dropped by policy; if src/ starts reading it this test must fail first`);
    assert.equal(classifyHeader(name), "dropped");
  }
});

test("the semantic corpus is a fixed, deterministic list of unique cases with exact expectations", () => {
  assert.equal(SEMANTIC_CORPUS.length, SEMANTIC_CORPUS_FIXED_COUNT);
  assert.equal(SEMANTIC_CORPUS_FIXED_COUNT, 18);
  assert.equal(new Set(SEMANTIC_CORPUS.map((entry) => entry.id)).size, 18);
  for (const entry of SEMANTIC_CORPUS) { assert.match(entry.id, /^[a-z0-9_]+$/); assert.ok(entry.id.length <= 31, `${entry.id}: the evidence scanner treats 32+ characters as a token`); }
  const reasons = SEMANTIC_CORPUS.flatMap((entry) => (entry.expect.kind === "reject" ? [entry.expect.reason] : []));
  assert.equal(reasons.length, 14);
  assert.deepEqual(Object.fromEntries(["a7.semantic_duplicate", "a7.semantic_value_invalid", "a7.semantic_refused_header"].map((reason) => [reason, reasons.filter((candidate) => candidate === reason).length])), { "a7.semantic_duplicate": 2, "a7.semantic_value_invalid": 3, "a7.semantic_refused_header": 9 });
  assert.equal(SEMANTIC_CORPUS.filter((entry) => entry.expect.kind === "pass").length, 4);
  assert.equal(SEMANTIC_EXPECTED_DROPPED, 6);
  const built = SEMANTIC_CORPUS.map((entry) => entry.build({ port: 1234 }, "N".repeat(22)).head.toString("latin1"));
  assert.deepEqual(SEMANTIC_CORPUS.map((entry) => entry.build({ port: 1234 }, "N".repeat(22)).head.toString("latin1")), built, "building a case twice yields identical bytes");
});

test("the direct known-address corpus is a fixed list of 110 unique requests with exact expectations and exactly three positive controls", () => {
  assert.equal(DIRECT_ENTRIES.length, DIRECT_CORPUS_FIXED_COUNT);
  assert.equal(DIRECT_CORPUS_FIXED_COUNT, 110);
  assert.equal(new Set(DIRECT_ENTRIES.map((entry) => entry.id)).size, 110);
  for (const entry of DIRECT_ENTRIES) { assert.match(entry.id, /^[a-z0-9_]+$/); assert.ok(entry.id.length <= 31, `${entry.id} is within the evidence scanner's limit`); }
  const family = (target: string, name: string) => DIRECT_ENTRIES.filter((entry) => entry.target === target && entry.family === name).length;
  assert.deepEqual(
    { noProof: family("boundary", "no_proof"), spoof: family("boundary", "spoof"), malformed: family("boundary", "malformed"), binding: family("boundary", "binding"), hop: family("boundary", "hop"), time: family("boundary", "time"), forged: family("boundary", "forged"), semantic: family("boundary", "semantic"), crossHop: family("boundary", "cross_hop"), replay: family("boundary", "replay") },
    { noProof: 10, spoof: 4, malformed: 9, binding: 8, hop: 2, time: 4, forged: 2, semantic: 36, crossHop: 4, replay: 10 },
  );
  assert.deepEqual({ noProof: family("app", "no_proof"), crossHop: family("app", "cross_hop"), semantic: family("app", "semantic"), replay: family("app", "replay") }, { noProof: 3, crossHop: 9, semantic: 4, replay: 5 });
  assert.equal(DIRECT_ENTRIES.filter((entry) => entry.target === "boundary").length, 89);
  assert.equal(DIRECT_ENTRIES.filter((entry) => entry.target === "app").length, 21);
  assert.deepEqual([...DIRECT_POSITIVE_CONTROLS].sort(), ["ap_first_use", "rp_seq_first_use", "rp_stall_winner"]);
  // lanes: refused cases are on the rejected lanes, positive controls on their own lanes, nothing on `protected`
  for (const entry of DIRECT_ENTRIES) {
    if (entry.expect.kind === "admit_once") assert.ok(entry.lane === (entry.target === "boundary" ? "positive_control_boundary" : "positive_control_app"), entry.id);
    else assert.equal(entry.lane, entry.target === "boundary" ? "direct_boundary_rejected" : "direct_app_rejected", entry.id);
  }
  assert.equal(DIRECT_ENTRIES.filter((entry) => entry.expect.kind !== "admit_once").length, 107);
  for (const entry of DIRECT_ENTRIES) if (entry.expect.kind === "reject") assert.ok((OB_REASONS as readonly string[]).includes(entry.expect.reason), `${entry.id}: ${entry.expect.reason} is in the closed list`);
  assert.equal(DIRECT_ENTRIES.filter((entry) => entry.expect.kind === "parser").length, 1, "one duplicated Content-Length that the HTTP parser itself refuses");
  assert.equal(DIRECT_SCENARIOS.flatMap((scenario) => scenario.entries).length, 110);
  // exactly one scenario is the startup fence probe
  assert.deepEqual(DIRECT_SCENARIOS.filter((scenario) => scenario.phase === "startup").flatMap((scenario) => scenario.entries.map((entry) => entry.id)), ["tm_before_fence"]);
});

test("every misuse the review required has a direct case: missing, malformed, modified body, wrong method, wrong target, expired, replayed, credential from another request", () => {
  const ids = new Set(DIRECT_ENTRIES.map((entry) => entry.id));
  for (const required of [
    "np_get_root", "mf_not_b64url", "bd_body_same_len", "bd_wrong_method", "bd_wrong_path", "tm_expired", "rp_seq_immediate", "bd_other_request_body",
    "sc_ct_altered", "sc_host_altered_authority", "sc_origin_altered", "sc_inj_xff", "sc_dup_host_differing", "sc_host_case_variant", "sc_origin_trailing_slash",
    "ap_compromised_boundary", "ap_pb_only", "ap_pb_in_ba_slot", "xh_ba_only_at_boundary", "xh_ba_in_pb_slot", "rp_stall_replay_1", "rp_abort_burn", "rp_abort_replay", "ap_fresh_ba_same_pb", "tm_before_fence",
  ]) assert.ok(ids.has(required), required);
});
