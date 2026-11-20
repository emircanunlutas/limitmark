import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { z } from "zod";

// M1 conformance model. All inputs are local documents or simulated verifier output.
const id = z.string().regex(/^[a-z][a-z0-9-]{0,63}$/);
const count = z.number().int().min(0).max(65_535);
const positiveCount = count.min(1);
const size = z.number().int().min(0).max(1_073_741_824);
const duration = z.number().int().min(0).max(2_147_483_647);
const access = z.enum(["public", "operational"]);
const segment = /^[A-Za-z0-9._~-]{1,64}$/;
const parameter = /^:[a-z][a-z0-9-]{0,31}$/;

function validPath(value: string, template: boolean): boolean {
  if (value === "/") return true;
  if (!value.startsWith("/")) return false;
  const parts = value.slice(1).split("/");
  return parts.length <= 16 && parts.every(part =>
    (template && parameter.test(part)) || (part !== "." && part !== ".." && segment.test(part)));
}

function validAuthority(value: string): boolean {
  const [host, port, extra] = value.split(":");
  return extra === undefined && host.length <= 253 &&
    host.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) &&
    (port === undefined || (/^[1-9][0-9]{0,4}$/.test(port) && Number(port) <= 65535));
}

const query = z.string().regex(/^(?:[A-Za-z0-9._~-]{1,64}=[A-Za-z0-9._~-]{1,64})?$/);
const channel = z.strictObject({
  id, access, principal: id, audience: id, scheme: z.enum(["http", "https"]),
  authority: z.string().max(259).refine(validAuthority),
});
const bucket = z.strictObject({
  id, access, reservedUnits: count, maxActiveUnits: positiveCount, maxQueued: count, maxWaitMs: duration,
});
const operation = z.strictObject({
  id, channel: id, classId: id, costUnits: positiveCount, effect: z.enum(["read", "write"]),
  method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]),
  path: z.string().max(1024).refine(value => validPath(value, true)), queries: z.array(query).min(1).max(32),
  body: z.strictObject({
    mediaType: z.string().max(127).regex(/^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*$/),
    maxBytes: size.min(1), requireSameOrigin: z.boolean(),
  }).nullable(),
});
const journey = z.strictObject({
  id, minCompletionBps: z.number().int().min(1).max(10000), p95LimitMs: duration.min(1), recoveryLimitMs: duration.min(1),
  steps: z.array(z.strictObject({
    operationId: id, target: z.string().max(1024), status: z.number().int().min(200).max(399),
    result: z.string().trim().min(1).max(256), receipt: id.nullable(),
  })).min(1).max(32),
});
const schema = z.strictObject({
  version: z.literal("customer-origin-policy-v1"), revision: positiveCount, tenantId: id, deploymentId: id,
  requestProfile: z.literal("bounded-http-v1"), unsupported: z.literal("deny"),
  domain: z.strictObject({ id, backendRef: id, instances: z.literal(1) }),
  channels: z.array(channel).min(1).max(16),
  capacity: z.strictObject({
    activeUnits: positiveCount, maxQueued: count, maxQueuedBytes: size,
    maxBodyBytes: size, metadataBytesPerRequest: size.min(1),
    proofWindowMs: duration.min(1), dispatchMarginMs: duration.min(1),
    executionTimeoutMs: duration.min(1), callerBudgetMs: duration.min(1),
  }),
  classes: z.array(bucket).min(1).max(32), operations: z.array(operation).min(1).max(128),
  journeys: z.array(journey).min(1).max(32),
});
type Manifest = z.infer<typeof schema>;
type Operation = z.infer<typeof operation>;

function unique(values: string[], field: string) {
  assert.equal(new Set(values).size, values.length, "duplicate " + field);
}

function intersectPaths(left: string, right: string): boolean {
  // Inputs have already passed the grammar. A parameter consumes exactly one nonempty segment.
  if (left === "/" || right === "/") return left === right;
  const leftParts = left.slice(1).split("/");
  const rightParts = right.slice(1).split("/");
  return leftParts.length === rightParts.length && leftParts.every((part, index) =>
    part === rightParts[index] || parameter.test(part) || parameter.test(rightParts[index]));
}

function matchesTarget(rule: Operation, target: string): boolean {
  if (target.length > 1024) return false;
  const [pathname, search, extra] = target.split("?");
  return extra === undefined && search !== "" && validPath(pathname, false) &&
    rule.queries.includes(search ?? "") && intersectPaths(rule.path, pathname);
}

function validate(input: unknown): Manifest {
  const p = schema.parse(input);
  for (const entries of [p.channels, p.classes, p.operations, p.journeys]) unique(entries.map(e => e.id), "id");
  unique(p.channels.map(c => JSON.stringify([c.principal, c.audience, c.scheme, c.authority])), "channel binding");
  const publicChannels = p.channels.filter(c => c.access === "public");
  for (const ops of p.channels.filter(c => c.access === "operational")) {
    assert.ok(publicChannels.every(c => c.principal !== ops.principal), "public operational principal reuse");
    assert.ok(publicChannels.every(c => c.audience !== ops.audience), "public operational audience reuse");
  }
  const limits = p.capacity;
  const shared = limits.activeUnits - p.classes.reduce((sum, c) => sum + c.reservedUnits, 0);
  assert.ok(shared >= 0, "overcommitted reservations");
  assert.equal(limits.maxQueued === 0, limits.maxQueuedBytes === 0, "queue count/bytes disagree");
  assert.ok(!limits.maxQueued || limits.maxQueuedBytes >= limits.metadataBytesPerRequest, "queue metadata cannot fit");
  for (const c of p.classes) {
    assert.ok(c.reservedUnits <= c.maxActiveUnits && c.maxActiveUnits <= c.reservedUnits + shared, "invalid class ceiling");
    assert.ok(c.maxQueued <= limits.maxQueued && (c.maxQueued === 0) === (c.maxWaitMs === 0), "invalid class queue");
    assert.ok(c.maxWaitMs + limits.dispatchMarginMs < limits.proofWindowMs, "wait exceeds proof budget");
    assert.ok(c.maxWaitMs + limits.dispatchMarginMs + limits.executionTimeoutMs <= limits.callerBudgetMs, "wait exceeds caller budget");
  }
  for (const [index, op] of p.operations.entries()) {
    const source = p.channels.find(c => c.id === op.channel);
    const owner = p.classes.find(c => c.id === op.classId);
    assert.ok(source && owner, "unknown channel or class");
    assert.equal(source.access, owner.access, "channel lacks class access");
    assert.ok(op.costUnits <= owner.maxActiveUnits && (!owner.reservedUnits || op.costUnits <= owner.reservedUnits), "cost cannot fit");
    const read = op.method === "GET" || op.method === "HEAD";
    assert.equal(op.effect, read ? "read" : "write", "method/effect mismatch");
    assert.ok(!read || op.body === null, "read body unsupported");
    assert.ok(!op.body || op.body.maxBytes <= limits.maxBodyBytes, "body exceeds domain limit");
    unique(op.queries, "query");
    unique(op.path.split("/").filter(part => parameter.test(part)), "parameter");
    const overlaps = p.operations.slice(0, index).find(other => other.channel === op.channel && other.method === op.method &&
      intersectPaths(other.path, op.path) && other.queries.some(q => op.queries.includes(q)));
    assert.ok(!overlaps, "overlapping operations: " + overlaps?.id + " and " + op.id);
  }
  const covered = new Set<string>();
  for (const j of p.journeys) {
    for (const step of j.steps) {
      const op = p.operations.find(entry => entry.id === step.operationId);
      assert.ok(op && matchesTarget(op, step.target), "journey step does not match its operation");
      assert.equal(step.receipt !== null, op.effect === "write", "journey receipt disagrees with effect");
      covered.add(op.id);
    }
  }
  assert.equal(covered.size, p.operations.length, "operation missing from journeys");
  return p;
}

function decodeDocument(bytes: Buffer) {
  assert.ok(bytes.length <= 262144, "manifest too large");
  const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  let decodedMembers = 0;
  const input: unknown = JSON.parse(source, (_key, value: unknown) => {
    if (typeof value === "object" && value !== null && !Array.isArray(value)) decodedMembers += Object.keys(value).length;
    return value;
  });
  // For valid JSON, only an object member name is a string token followed by a colon.
  const memberTokens = [...source.matchAll(/"(?:\\.|[^"\\])*"\s*(:)?/g)].filter(match => match[1] !== undefined);
  assert.equal(memberTokens.length, decodedMembers, "duplicate JSON member");
  return { manifest: validate(input), digest: createHash("sha256").update(bytes).digest("hex") };
}

const fixture = (name: string) => decodeDocument(readFileSync(path.join(__dirname, "fixtures", "customer-origin-v1", name)));
const demo = fixture("ba0.json");
const shop = fixture("storefront.json");
type Policy = typeof shop;
type Scope = { tenantId: string; deploymentId: string; domainId: string; digest: string };
type Facts = {
  principal: string; audience: string; scheme: string; authority: string;
  method: string; target: string; mediaType: string | null; bodyBytes: number; origin: string | null;
};
const verified = Symbol("synthetic verifier success");
type Verified = Facts & Scope & { [verified]: true };

function classify({ manifest: p, digest }: Policy, request: Verified | null) {
  if (!request || request[verified] !== true) return { kind: "unverified" } as const;
  if (request.tenantId !== p.tenantId || request.deploymentId !== p.deploymentId ||
      request.domainId !== p.domain.id || request.digest !== digest) return { kind: "scope-mismatch" } as const;
  const source = p.channels.find(c => c.principal === request.principal && c.audience === request.audience &&
    c.scheme === request.scheme && c.authority === request.authority);
  if (!source) return { kind: "untrusted-channel" } as const;
  const op = p.operations.find(candidate => candidate.channel === source.id &&
    candidate.method === request.method && matchesTarget(candidate, request.target));
  if (!op || !Number.isSafeInteger(request.bodyBytes) || request.bodyBytes < 0 ||
      request.mediaType !== (op.body?.mediaType ?? null) || request.bodyBytes > (op.body?.maxBytes ?? 0) ||
      (op.body?.requireSameOrigin && request.origin !== source.scheme + "://" + source.authority)) {
    return { kind: "unsupported" } as const;
  }
  return { kind: "classified", operationId: op.id, classId: op.classId, costUnits: op.costUnits } as const;
}

// Only this test double supplies verified facts. It performs no authentication or transport I/O.
function observation(policy: Policy, channelId: string, method: string, target: string, overrides: Partial<Facts & Scope> = {}): Verified {
  const p = policy.manifest;
  const c = p.channels.find(entry => entry.id === channelId);
  assert.ok(c);
  return {
    [verified]: true, tenantId: p.tenantId, deploymentId: p.deploymentId, domainId: p.domain.id, digest: policy.digest,
    principal: c.principal, audience: c.audience, scheme: c.scheme, authority: c.authority,
    method, target, mediaType: null, bodyBytes: 0, origin: null, ...overrides,
  };
}

// An occupancy example describes one instant. This predicate checks the contract inequalities;
// it does not acquire, enqueue, dispatch, settle or otherwise implement a capacity controller.
type Occupancy = { classId: string; reserved: number; shared: number; queuedBodyBytes: number[] };
function withinBudget(p: Manifest, rows: Occupancy[]): boolean {
  const limits = p.capacity;
  const sharedLimit = limits.activeUnits - p.classes.reduce((sum, c) => sum + c.reservedUnits, 0);
  let shared = 0;
  let queued = 0;
  let retained = 0;
  if (new Set(rows.map(r => r.classId)).size !== rows.length) return false;
  for (const r of rows) {
    const c = p.classes.find(entry => entry.id === r.classId);
    if (!c || ![r.reserved, r.shared].every(n => Number.isSafeInteger(n) && n >= 0) ||
        r.reserved > c.reservedUnits || r.shared > c.maxActiveUnits - c.reservedUnits ||
        r.queuedBodyBytes.length > c.maxQueued) return false;
    for (const bytes of r.queuedBodyBytes) {
      if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > limits.maxBodyBytes) return false;
      retained += limits.metadataBytesPerRequest + bytes;
    }
    shared += r.shared;
    queued += r.queuedBodyBytes.length;
  }
  return shared <= sharedLimit && queued <= limits.maxQueued && retained <= limits.maxQueuedBytes;
}

test("the two documents select different tenants, deployments and single fixed backends", () => {
  for (const p of [demo, shop]) {
    assert.equal(p.manifest.domain.instances, 1);
    assert.equal(p.manifest.unsupported, "deny");
    assert.match(p.digest, /^[0-9a-f]{64}$/);
  }
  assert.notEqual(shop.manifest.tenantId, demo.manifest.tenantId);
  assert.notEqual(shop.manifest.deploymentId, demo.manifest.deploymentId);
  assert.notEqual(shop.manifest.domain.backendRef, demo.manifest.domain.backendRef);
  const newEdition = decodeDocument(Buffer.from(JSON.stringify({ ...shop.manifest, revision: 2 })));
  assert.equal(classify(newEdition, observation(shop, "shopper", "GET", "/products/lamp-7")).kind, "scope-mismatch");
});

type Example = [method: string, target: string, operationId: string, classId: string, cost: number, facts?: Partial<Facts>];
function expectMappings(policy: Policy, channelId: string, cases: Example[]) {
  for (const [method, target, operationId, classId, costUnits, facts] of cases) {
    assert.deepEqual(classify(policy, observation(policy, channelId, method, target, facts)),
      { kind: "classified", operationId, classId, costUnits }, method + " " + target);
  }
}

test("BA0 maps its five journey operations and all four supported query variants", () => {
  expectMappings(demo, "visitor", [
    ["GET", "/", "home", "information", 1], ["GET", "/gizlilik", "privacy", "information", 1],
    ["GET", "/test-talep-et", "inquiry-form", "form-read", 1],
    ["GET", "/test-talep-et/tesekkurler", "confirmation", "form-read", 1],
    ["POST", "/api/public-inquiries", "submit-inquiry", "submission", 2,
      { mediaType: "application/x-www-form-urlencoded", bodyBytes: 32768, origin: "http://127.0.0.1:18080" }],
  ]);
  for (const value of ["web", "network", "protection", "unsure"]) {
    expectMappings(demo, "visitor", [["GET", "/test-talep-et?hizmet=" + value, "inquiry-form", "form-read", 1]]);
  }
  for (const target of ["/test-talep-et?", "/test-talep-et?hizmet=other", "/test-talep-et?hizmet=web&hizmet=web"]) {
    assert.equal(classify(demo, observation(demo, "visitor", "GET", target)).kind, "unsupported");
  }
});

const orderFacts = { mediaType: "application/json", bodyBytes: 8192, origin: "https://shop.example.test" };
const stockFacts = { mediaType: "application/json", bodyBytes: 2048 };
test("product, asset, reserved checkout, bounded order and warehouse use independent operation mappings", () => {
  expectMappings(shop, "shopper", [
    ["GET", "/products/lamp-7", "product", "browse", 1], ["GET", "/products/table-3", "product", "browse", 1],
    ["GET", "/assets/lamp-7.webp", "product-image", "asset", 1], ["GET", "/checkout/cart-7", "checkout-summary", "checkout", 1],
    ["POST", "/orders", "place-order", "orders", 2, orderFacts],
  ]);
  expectMappings(shop, "warehouse", [["PATCH", "/inventory/lamp-7", "adjust-stock", "inventory", 2, stockFacts]]);
});

test("only verified, tenant-, deployment-, domain- and policy-bound facts classify", () => {
  const request = observation(shop, "shopper", "GET", "/checkout/cart-7");
  const { [verified]: marker, ...wireFields } = request;
  assert.equal(marker, true);
  assert.equal(classify(shop, null).kind, "unverified");
  assert.equal(classify(shop, { ...wireFields, verified: true } as unknown as Verified).kind, "unverified");
  for (const key of ["tenantId", "deploymentId", "domainId", "digest"] as const) {
    assert.equal(classify(shop, { ...request, [key]: "other" }).kind, "scope-mismatch", key);
  }
  for (const key of ["principal", "audience", "scheme", "authority"] as const) {
    assert.equal(classify(shop, { ...request, [key]: "other" }).kind, "untrusted-channel", key);
  }
});

test("a public request cannot claim an operational reservation on the same hostname", () => {
  const visitor = observation(shop, "shopper", "PATCH", "/inventory/lamp-7", stockFacts);
  const spoof = { ...visitor, channel: "warehouse", classId: "inventory", priority: "operational" };
  assert.equal(classify(shop, spoof).kind, "unsupported");
  assert.equal(classify(shop, { ...spoof, audience: "shop-operations" }).kind, "untrusted-channel");
  assert.equal(classify(shop, { ...spoof, principal: "stock-service" }).kind, "untrusted-channel");
});

test("a public alias can reuse its trust binding while retaining its own exact authority and route inventory", () => {
  const alias = changed(p => {
    p.channels.push({ ...p.channels[0], id: "catalog", authority: "catalog.example.test" });
    p.operations.push({ ...p.operations[0], id: "catalog-product", channel: "catalog" });
    p.journeys[0].steps.push({ ...p.journeys[0].steps[0], operationId: "catalog-product" });
  });
  const policy = decodeDocument(Buffer.from(JSON.stringify(alias)));
  expectMappings(policy, "catalog", [["GET", "/products/lamp-7", "catalog-product", "browse", 1]]);
  assert.equal(classify(policy, observation(policy, "catalog", "POST", "/orders", orderFacts)).kind, "unsupported");
});

test("unlisted requests, ambiguous encodings and incompatible body facts have no class or budget", () => {
  for (const target of ["/", "/products", "/products/", "/products/.", "/products/..", "/products//a",
    "/products/%2f", "/products/a/b", "/products/a?sku=a", "/products/a#x", "/products/:sku", "/products/a\\b"]) {
    assert.deepEqual(classify(shop, observation(shop, "shopper", "GET", target)), { kind: "unsupported" }, target);
  }
  for (const method of ["HEAD", "DELETE", "OPTIONS", "get"]) {
    assert.equal(classify(shop, observation(shop, "shopper", method, "/products/lamp-7")).kind, "unsupported", method);
  }
  const post = observation(shop, "shopper", "POST", "/orders", orderFacts);
  for (const change of [{ bodyBytes: 8193 }, { bodyBytes: -1 }, { bodyBytes: 0.5 }, { mediaType: "text/plain" },
    { origin: "https://other.example.test" }, { origin: null }, { mediaType: null }]) {
    assert.deepEqual(classify(shop, { ...post, ...change }), { kind: "unsupported" });
  }
  for (const change of [{ bodyBytes: 1 }, { mediaType: "application/json" }]) {
    assert.equal(classify(shop, observation(shop, "shopper", "GET", "/products/lamp-7", change)).kind, "unsupported");
  }
});

function changed(edit: (p: Manifest) => void): Manifest {
  const p = structuredClone(shop.manifest);
  edit(p);
  return p;
}

test("overlap rejection is order independent and includes intersecting templates and query sets", () => {
  for (const route of ["/products/:sku", "/products/:item", "/products/special"]) {
    const candidate = changed(p => { p.operations.push({ ...p.operations[0], id: "second", path: route, queries: ["", "view=full"] }); });
    assert.throws(() => validate(candidate), /overlapping operations/);
    candidate.operations.reverse();
    assert.throws(() => validate(candidate), /overlapping operations/);
  }
  const crossing = changed(p => {
    p.operations[0].path = "/:section/featured";
    p.operations[1].path = "/products/:item";
  });
  assert.throws(() => validate(crossing), /overlapping operations/);
  const disjoint = changed(p => {
    p.operations.push({ ...p.operations[0], id: "detail", queries: ["view=full"] });
    p.journeys[0].steps.push({ ...p.journeys[0].steps[0], operationId: "detail", target: "/products/lamp-7?view=full" });
  });
  assert.doesNotThrow(() => validate(disjoint));
});

test("the closed document rejects unknown versions, options, multiple domains and duplicate JSON members", () => {
  for (const unknown of [{ version: "v2" }, { requestProfile: "streaming" }, { unsupported: "pass" },
    { domains: [shop.manifest.domain, shop.manifest.domain] }, { tenantId: "" }, { deploymentId: "" },
    { domain: { ...shop.manifest.domain, instances: 2 } }, { domain: { ...shop.manifest.domain, dynamicUpstream: true } }]) {
    assert.throws(() => validate({ ...shop.manifest, ...unknown }));
  }
  const original = JSON.stringify(shop.manifest);
  const repeated = original.replace('"revision":1', '"revision":2,"\\u0072evision":1');
  assert.throws(() => decodeDocument(Buffer.from(repeated)), /duplicate JSON member/);
  assert.throws(() => decodeDocument(Buffer.alloc(262145)), /manifest too large/);
});

const invalidConfigs: [string, (p: Manifest) => void, RegExp][] = [
  ["duplicate operation", p => { p.operations[1].id = p.operations[0].id; }, /duplicate id/],
  ["ambiguous channel binding", p => { p.channels.push({ ...p.channels[0], id: "other" }); }, /duplicate channel binding/],
  ["reused operational principal", p => { p.channels[1].principal = p.channels[0].principal; }, /operational principal reuse/],
  ["reused operational audience", p => { p.channels[1].audience = p.channels[0].audience; }, /operational audience reuse/],
  ["unbound channel", p => { p.operations[0].channel = "missing"; }, /unknown channel or class/],
  ["unbound class", p => { p.operations[0].classId = "missing"; }, /unknown channel or class/],
  ["public operational rule", p => { p.operations[4].channel = "shopper"; }, /channel lacks class access/],
  ["unknown template operator", p => { p.operations[0].path = "/products/*"; }, /path/],
  ["duplicate query", p => { p.operations[0].queries.push(""); }, /duplicate query/],
  ["inconsistent effect", p => { p.operations[0].effect = "write"; }, /method\/effect mismatch/],
  ["body on read", p => { p.operations[0].body = p.operations[3].body; }, /read body unsupported/],
  ["oversize operation body", p => { p.capacity.maxBodyBytes = 1024; }, /body exceeds domain/],
  ["overcommitted floors", p => { p.capacity.activeUnits = 8; }, /overcommitted reservations/],
  ["ceiling below floor", p => { p.classes[2].maxActiveUnits = 2; }, /invalid class ceiling/],
  ["ceiling invades another floor", p => { p.classes[0].maxActiveUnits = 8; }, /invalid class ceiling/],
  ["unusable reservation", p => { p.operations[3].costUnits = 5; }, /cost cannot fit/],
  ["cost above ceiling", p => { p.operations[0].costUnits = 6; }, /cost cannot fit/],
  ["per-class queue above total", p => { p.classes[0].maxQueued = 11; }, /invalid class queue/],
  ["wait without queue", p => { p.classes[1].maxWaitMs = 1; }, /invalid class queue/],
  ["queue without wait", p => { p.classes[0].maxWaitMs = 0; }, /invalid class queue/],
  ["queue without byte limit", p => { p.capacity.maxQueuedBytes = 0; }, /queue count\/bytes/],
  ["metadata too large", p => { p.capacity.maxQueuedBytes = 512; }, /queue metadata cannot fit/],
  ["proof too short", p => { p.capacity.proofWindowMs = 200; }, /wait exceeds proof budget/],
  ["caller deadline too short", p => { p.capacity.callerBudgetMs = 2199; }, /wait exceeds caller budget/],
  ["nonfinite ceiling", p => { p.capacity.activeUnits = Infinity; }, /activeUnits/],
  ["fractional queue bound", p => { p.classes[0].maxQueued = 1.5; }, /maxQueued/],
  ["negative byte budget", p => { p.capacity.maxQueuedBytes = -1; }, /maxQueuedBytes/],
  ["wrong journey target", p => { p.journeys[0].steps[0].target = "/checkout/cart-7"; }, /journey step/],
  ["missing operation", p => { p.journeys[0].steps[0].operationId = "missing"; }, /journey step/],
  ["mutation with no receipt", p => { p.journeys[0].steps[3].receipt = null; }, /journey receipt/],
  ["read with a commit", p => { p.journeys[0].steps[0].receipt = "order-committed"; }, /journey receipt/],
  ["uncovered operation", p => { p.journeys.pop(); }, /operation missing from journeys/],
];
for (const [name, edit, expected] of invalidConfigs) {
  test("invalid manifest rejects " + name, () => assert.throws(() => validate(changed(edit)), expected));
}

test("a full shared pool leaves checkout, order and operational reservations available", () => {
  const rows: Occupancy[] = [
    { classId: "browse", reserved: 0, shared: 5, queuedBodyBytes: [] },
    { classId: "asset", reserved: 0, shared: 2, queuedBodyBytes: [] },
    { classId: "checkout", reserved: 3, shared: 0, queuedBodyBytes: [] },
    { classId: "orders", reserved: 4, shared: 0, queuedBodyBytes: [] },
    { classId: "inventory", reserved: 2, shared: 0, queuedBodyBytes: [] },
  ];
  assert.equal(withinBudget(shop.manifest, rows), true);
  assert.equal(withinBudget(shop.manifest, [...rows.slice(0, 1), { ...rows[1], shared: 3 }]), false, "unused floors stay exclusive");
  assert.equal(withinBudget(shop.manifest, [{ ...rows[0], reserved: 1 }]), false);
  assert.equal(withinBudget(shop.manifest, [{ ...rows[3], shared: 3 }]), false, "orders exceed their elastic allowance");
});

test("class count, domain count and retained bytes bound independent queue snapshots", () => {
  const queued = (classId: string, queuedBodyBytes: number[]): Occupancy => ({ classId, reserved: 0, shared: 0, queuedBodyBytes });
  const rows = [queued("browse", [0, 0]), queued("checkout", [0, 0, 0, 0, 0]), queued("orders", [8192, 8192, 8192])];
  assert.equal(withinBudget(shop.manifest, rows), true);
  assert.equal(withinBudget(shop.manifest, [...rows, queued("inventory", [0])]), false, "11 waiters exceed domain count");
  assert.equal(withinBudget(shop.manifest, [queued("asset", [0])]), false, "asset class never waits");
  const demoQueue = (length: number) => queued("submission", [32768, length]);
  assert.equal(withinBudget(demo.manifest, [demoQueue(28672)]), true, "two metadata charges and bodies fit exactly");
  assert.equal(withinBudget(demo.manifest, [demoQueue(28673)]), false, "count fits but bytes exceed budget by one");
});

test("ordered journey expectations distinguish reads, synthetic mutation and durable customer outcomes", () => {
  const expected = [
    ["demo-inquiry", ["home", "privacy", "inquiry-form", "submit-inquiry", "confirmation"], [200, 200, 200, 200, 200], [null, null, null, "synthetic-app-mutation", null]],
    ["purchase", ["product", "product-image", "checkout-summary", "place-order"], [200, 200, 200, 201], [null, null, null, "order-committed"]],
    ["stock-correction", ["adjust-stock"], [204], ["stock-adjustment-committed"]],
  ];
  assert.deepEqual([...demo.manifest.journeys, ...shop.manifest.journeys].map(j => [
    j.id, j.steps.map(s => s.operationId), j.steps.map(s => s.status), j.steps.map(s => s.receipt),
  ]), expected);
});
