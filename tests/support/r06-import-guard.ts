import { readdir, readFile } from "node:fs/promises";
import { join, posix, relative } from "node:path";
import * as ts from "typescript";

// R06 activation tooling (remediation B4): STRUCTURAL capability and import analysis. The earlier guard matched `import { ... } from "..."`
// with a regular expression, which a namespace import, a dynamic import(), require()/createRequire(), a re-export, an aliased or
// destructured or computed-property access to the signer all walk straight past. This analyzer parses the source with the TypeScript
// compiler API and reasons about the syntax tree:
//
//   1. `collectModuleReferences` reports EVERY way a module can be referenced -- static import (default / namespace / named / side-effect /
//      type-only), `export ... from`, `import x = require()`, dynamic `import()`, `require()`, `createRequire`, `module.require`,
//      `import.meta.resolve`, `import("x")` types -- with the imported names where they are statically known.
//   2. `moduleReferenceViolations` applies a per-file policy to references of guarded modules: named imports of allowlisted names only.
//      Everything else (default, namespace, side-effect, re-export, dynamic, require, computed specifier) is a violation.
//   3. `referenceShapeViolations` constrains HOW an imported binding may be used: every reference must be one exact syntactic shape, so a
//      binding cannot be aliased, stored, passed, destructured or reached through a computed property.
//
//   4. (remediation F2) `indirectAccessViolations` forbids, in the security-sensitive tooling, every way of reaching `require`, `eval`, the
//      Function constructor, the global object or `process.mainModule` WITHOUT naming a module: the names are banned outright (any
//      identifier or string occurrence), `process` may only appear as `process.<reviewed property>`, `import.meta` only as `.url`, and a call
//      may only go through an identifier or a property access (never `(0, f)(x)`, `f()(x)` or `obj[key](x)`).
//   5. (remediation F2) the repository scan FAILS CLOSED: a reference whose module cannot be proven (computed `import()`/`require()`,
//      `createRequire`, an aliased or indirectly obtained `require`) is reported by `unprovableReferences` instead of being skipped, a
//      symlink the scan cannot follow is an error, and only an exact, justified list of generated/dependency directories is excluded.
//
// Pure functions over source text (no I/O) so each bypass has a negative control; `scanRepository` is the only file reader.

export type ReferenceKind = "import" | "export-from" | "import-equals" | "dynamic-import" | "require" | "create-require" | "module-require" | "import-meta-resolve" | "import-type";
export type ReferenceShape = "named" | "default" | "namespace" | "side-effect" | "star-export" | "computed" | "specifier";
export type ModuleReference = {
  kind: ReferenceKind;
  shape: ReferenceShape;
  /** The literal module specifier, or null when it is not a string literal (a computed specifier is itself a bypass). */
  specifier: string | null;
  /** Original (pre-alias) exported names for named imports/exports; empty otherwise. */
  names: string[];
  typeOnly: boolean;
  line: number;
};

/** Objects through which a computed property name can reach `require`, `eval` or the module system. */
const HOST_OBJECTS: ReadonlySet<string> = new Set(["globalThis", "global", "module", "process"]);

const literalText = (node: ts.Node | undefined): string | null =>
  node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) ? node.text : null;

// ---------------------------------------------------------------------------
// Fifth-audit remediation (importer closure): the ACCEPTED SPECIFIER GRAMMAR
// ---------------------------------------------------------------------------
//
// The previous analyzer attributed a reference to a protected module by the last path segment and DENYLISTED a few odd spellings. The audit
// showed the denylist is open-ended on Windows: `x.ts::$DATA` (NTFS alternate data stream) and `STAGIN~1.TS` (8.3 short name) both load the
// module under a last segment nobody attributes, and `#k` / a tsconfig path alias load it under no recognizable name at all. So the rule is
// inverted: a specifier is PROVABLE only if it matches this narrow, reviewed grammar; every other literal is reported as an UNPROVABLE
// reference (specifier null), which the repository scan treats as a failure exactly like a computed specifier.
//
//   node built-in      `node:` + lower-case name segments                  node:fs/promises
//   Worker built-in    `cloudflare:` + a lower-case name                    cloudflare:workers
//   relative           `./` or `../` + path segments                         ../operator/staging-attestation-key.ts
//   repository alias   `@/` + path segments (the one reviewed tsconfig path) @/lib/authority-result-trust
//   package            lower-case npm name (optionally scoped) + path        next/server, @playwright/test
//
// A path SEGMENT is `.`, `..`, or a non-empty run of [A-Za-z0-9._@-] that does not end in a dot. That excludes, by construction, `:` (ADS
// and URL schemes), `$`, `~` (8.3 short names), `%`, backslash, whitespace/control characters, non-ASCII, empty segments (`//`, a trailing
// slash), a trailing-dot segment (Windows strips it), absolute paths and drive letters. `?` and `#` are NOT accepted anywhere in a literal, and
// no query or fragment suffix is ever split off or interpreted (sixth-pass remediation): the CommonJS loader tsx runs here treats `#` as an
// ordinary path character and normalizes `..` lexically, so `../x#/../operator/staging-attestation-key.ts` loads the protected module while a
// suffix-splitting scanner attributes it to `x`. No reviewed import uses a query or fragment, so every literal containing either is unprovable.
// A specifier that STARTS with `#` (package.json `imports`) is likewise unprovable. Where a Windows file-system alias cannot be safely
// canonicalized the spelling is refused, never normalized.
const CONTROL_OR_ESCAPE = /[%\\?#\u0000- \u007f-￿]/u;
const SEGMENT_CHARACTERS = /^[A-Za-z0-9._@-]+$/u;
const validSegment = (segment: string): boolean => segment === "." || segment === ".." || (SEGMENT_CHARACTERS.test(segment) && !segment.endsWith("."));
const PACKAGE_NAME = /^[a-z0-9][a-z0-9._-]*$/u;
const NODE_BUILTIN = /^node:[a-z0-9_]+(?:\/[a-z0-9_]+)*$/u;
const WORKER_BUILTIN = /^cloudflare:[a-z]+$/u;

/** The kind of an ACCEPTED specifier, or null when the spelling is outside the reviewed grammar. */
export type SpecifierClass = "node-builtin" | "worker-builtin" | "relative" | "alias" | "package";
export function classifySpecifierPath(path: string): SpecifierClass | null {
  if (path.startsWith("node:")) return NODE_BUILTIN.test(path) ? "node-builtin" : null;
  if (path.startsWith("cloudflare:")) return WORKER_BUILTIN.test(path) ? "worker-builtin" : null;
  if (path.includes(":")) return null;
  const segments = path.split("/");
  if (path === "." || path === "..") return "relative";
  if (path.startsWith("./") || path.startsWith("../")) {
    // the LAST segment must name something: `x.ts/.` and `x.ts/..` are directory spellings that different loaders canonicalize differently
    const last = segments[segments.length - 1];
    return segments.every(validSegment) && last !== "." && last !== ".." ? "relative" : null;
  }
  if (path.startsWith("@/")) return segments.slice(1).every((segment) => validSegment(segment) && segment !== "." && segment !== "..") && segments.length > 1 ? "alias" : null;
  // a package: the first segment (or the first two, when scoped) is a lower-case npm name; the rest are plain path segments
  const scoped = path.startsWith("@");
  const nameSegments = scoped ? segments.slice(0, 2) : segments.slice(0, 1);
  if (scoped && segments.length < 2) return null;
  if (!nameSegments.every((segment, index) => (scoped && index === 0 ? PACKAGE_NAME.test(segment.slice(1)) : PACKAGE_NAME.test(segment)) && !segment.endsWith("."))) return null;
  return segments.slice(nameSegments.length).every((segment) => validSegment(segment) && segment !== "." && segment !== "..") ? "package" : null;
}

/** True when the whole literal is inside the accepted grammar (no control, whitespace, percent, backslash, `?` or `#` character anywhere). */
export const isAcceptedSpecifier = (specifier: string): boolean =>
  !CONTROL_OR_ESCAPE.test(specifier) && classifySpecifierPath(specifier) !== null;

const specifierText = (node: ts.Node | undefined): string | null => {
  const text = literalText(node);
  return text === null || !isAcceptedSpecifier(text) ? null : text;
};

// ---------------------------------------------------------------------------
// Parser-language agreement
// ---------------------------------------------------------------------------
//
// Each file is parsed in the language its extension means to the loader that really runs it here. Measured with this repository's tsx/esbuild:
// `.jsx` and `.tsx` accept JSX (JSX text such as `it's a 'quote and \`tick` is TEXT there); `.js`, `.mjs` and `.cjs` do NOT ("The JSX syntax
// extension is not currently enabled"); `.ts` / `.mts` / `.cts` are TypeScript. Parsing a `.jsx` file as plain TypeScript let an apostrophe or
// backtick in JSX text swallow the next real `import` (audit A3). The converse is handled by failing closed: JSX text in a `.js` / `.ts` file is
// a syntax error here exactly as it is at run time. A file that does not PARSE cleanly in its own language is a scanner FAILURE, never "zero
// references".
export class ScannerSyntaxError extends Error {
  constructor(readonly file: string, readonly detail: string) { super(`scanner cannot parse ${file}: ${detail}`); this.name = "ScannerSyntaxError"; }
}

export function scriptKindFor(fileName: string): ts.ScriptKind {
  const extension = /\.([cm]?[jt]sx?)$/iu.exec(fileName)?.[1]?.toLowerCase();
  if (extension === "tsx") return ts.ScriptKind.TSX;
  if (extension === "jsx") return ts.ScriptKind.JSX;
  // .js / .mjs / .cjs have no JSX at run time, so none here (ScriptKind.JS would silently ENABLE JSX and re-open the swallowed-import gap in reverse)
  return ts.ScriptKind.TS;
}

export function parseSource(source: string, fileName = "source.ts"): ts.SourceFile {
  const sourceFile = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, scriptKindFor(fileName));
  const diagnostics = (sourceFile as unknown as { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics;
  if (diagnostics === undefined) throw new ScannerSyntaxError(fileName, "the parser exposes no syntax diagnostics (cannot fail closed)");
  if (diagnostics.length > 0) {
    const first = diagnostics[0];
    const where = first.start === undefined ? 0 : sourceFile.getLineAndCharacterOfPosition(first.start).line + 1;
    throw new ScannerSyntaxError(fileName, `line ${where}: ${ts.flattenDiagnosticMessageText(first.messageText, " ")}`);
  }
  return sourceFile;
}

export function collectModuleReferences(source: string, fileName = "source.ts"): ModuleReference[] {
  const sourceFile = parseSource(source, fileName);
  const found: ModuleReference[] = [];
  const line = (node: ts.Node) => sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
  const computed = (kind: ReferenceKind, node: ts.Node) =>
    found.push({ kind, shape: "computed", specifier: null, names: [], typeOnly: false, line: line(node) });
  const visit = (node: ts.Node): void => {
    // F2: `require` obtained or used in ANY way other than a direct call is module access the specifier-based checks cannot name:
    // `(0, require)(x)`, `const r = require`, `Reflect.apply(require, ...)`, `{ require } = ...`, `x.require`, `globalThis["require"]`.
    if (ts.isIdentifier(node) && node.text === "require") {
      const parent = node.parent;
      const directCall = ts.isCallExpression(parent) && parent.expression === node;
      // only `module.require(...)` is recorded by the call handler below; `globalThis.require(...)` or `holder.require(...)` are not
      const propertyCall = ts.isPropertyAccessExpression(parent) && parent.name === node && ts.isIdentifier(parent.expression) && parent.expression.text === "module" &&
        ts.isCallExpression(parent.parent) && parent.parent.expression === parent;
      const declaredName = ts.isVariableDeclaration(parent) && parent.name === node;
      if (!directCall && !propertyCall && !declaredName) computed("require", node);
    }
    if (ts.isElementAccessExpression(node)) {
      const key = node.argumentExpression;
      const literalKey = ts.isStringLiteral(key) || ts.isNoSubstitutionTemplateLiteral(key);
      if (literalKey && key.text === "require") computed("require", node);
      else if (!literalKey && ts.isIdentifier(node.expression) && HOST_OBJECTS.has(node.expression.text)) computed("require", node);
    }
    if (ts.isImportDeclaration(node)) {
      const clause = node.importClause;
      const base = { kind: "import" as const, specifier: specifierText(node.moduleSpecifier), typeOnly: clause?.isTypeOnly ?? false, line: line(node) };
      if (!clause) found.push({ ...base, shape: "side-effect", names: [] });
      else {
        if (clause.name) found.push({ ...base, shape: "default", names: [] });
        const bindings = clause.namedBindings;
        if (bindings && ts.isNamespaceImport(bindings)) found.push({ ...base, shape: "namespace", names: [] });
        if (bindings && ts.isNamedImports(bindings))
          found.push({ ...base, shape: "named", names: bindings.elements.map((element) => (element.propertyName ?? element.name).text), typeOnly: base.typeOnly || bindings.elements.every((element) => element.isTypeOnly) });
      }
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier) {
      const base = { kind: "export-from" as const, specifier: specifierText(node.moduleSpecifier), typeOnly: node.isTypeOnly, line: line(node) };
      if (!node.exportClause || ts.isNamespaceExport(node.exportClause)) found.push({ ...base, shape: "star-export", names: [] });
      else found.push({ ...base, shape: "named", names: node.exportClause.elements.map((element) => (element.propertyName ?? element.name).text) });
    } else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
      found.push({ kind: "import-equals", shape: "specifier", specifier: specifierText(node.moduleReference.expression), names: [], typeOnly: node.isTypeOnly, line: line(node) });
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const argument = specifierText(node.arguments[0]);
      const record = (kind: ReferenceKind, specifier: string | null) =>
        found.push({ kind, shape: specifier === null ? "computed" : "specifier", specifier, names: [], typeOnly: false, line: line(node) });
      if (callee.kind === ts.SyntaxKind.ImportKeyword) record("dynamic-import", argument);
      else if (ts.isIdentifier(callee) && callee.text === "require") record("require", argument);
      else if (ts.isIdentifier(callee) && callee.text === "createRequire") record("create-require", null);
      else if (ts.isPropertyAccessExpression(callee) && callee.name.text === "createRequire") record("create-require", null);
      else if (ts.isPropertyAccessExpression(callee) && callee.name.text === "require" && ts.isIdentifier(callee.expression) && callee.expression.text === "module") record("module-require", argument);
      else if (ts.isPropertyAccessExpression(callee) && callee.name.text === "resolve" && ts.isMetaProperty(callee.expression)) record("import-meta-resolve", argument);
      else if (ts.isElementAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === "module") record("module-require", null);
    } else if (ts.isImportTypeNode(node)) {
      const argument = node.argument;
      found.push({ kind: "import-type", shape: "specifier", specifier: ts.isLiteralTypeNode(argument) ? specifierText(argument.literal) : null, names: [], typeOnly: true, line: line(node) });
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return found;
}

/** The module's CANONICAL name: the last path segment without a script extension, lower-cased (a case-insensitive file system -- Windows,
 * macOS -- resolves `Staging-Key` to `staging-key`). "../operator/Staging-Attestation-Key.TS" -> "staging-attestation-key". Matching on this
 * name only ATTRIBUTES a reference to a module; whether the spelling is acceptable and the exact file is intended is
 * `protectedReferenceViolations`' job. The specifier is taken literally: a `?` or `#` never reaches here from the collector (such a literal is
 * unprovable) and is never treated as the start of a suffix. */
export const moduleName = (specifier: string): string => (specifier.split("/").pop() ?? specifier).replace(/\.(?:[cm]?[jt]sx?)$/iu, "").toLowerCase();

export type ModulePolicy = Readonly<Record<string, readonly string[]>>;

/** Applies `policy` (guarded module name -> the only names that may be imported from it) to a file. Returns human-readable violations. */
export function moduleReferenceViolations(source: string, policy: ModulePolicy, fileName = "source.ts"): string[] {
  const violations: string[] = [];
  for (const reference of collectModuleReferences(source, fileName)) {
    const where = `line ${reference.line}`;
    if (reference.specifier === null) {
      // A computed specifier can name ANY module, including a guarded one: never acceptable in guarded tooling.
      violations.push(`${where}: computed or malformed ${reference.kind} specifier cannot be proven not to reach a guarded module`);
      continue;
    }
    const guarded = policy[moduleName(reference.specifier)];
    if (guarded === undefined) {
      if (reference.kind === "create-require" || reference.kind === "module-require") violations.push(`${where}: ${reference.kind} gives untracked module access`);
      continue;
    }
    const label = `${reference.kind} of ${moduleName(reference.specifier)}`;
    if (reference.kind !== "import") violations.push(`${where}: ${label} (only a static named import is allowed)`);
    else if (reference.shape !== "named") violations.push(`${where}: ${reference.shape} import of ${moduleName(reference.specifier)} (only named imports are allowed)`);
    else for (const name of reference.names) if (!guarded.includes(name)) violations.push(`${where}: ${name} is not an allowed import from ${moduleName(reference.specifier)}`);
  }
  return violations;
}

/** Code that can create module access the reference collector cannot name: eval and the Function constructor. */
export function dynamicCodeViolations(source: string, fileName = "source.ts"): string[] {
  const sourceFile = parseSource(source, fileName);
  const violations: string[] = [];
  const visit = (node: ts.Node): void => {
    const at = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && (node.expression.text === "eval" || node.expression.text === "Function")) violations.push(`line ${at}: ${node.expression.text}()`);
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "Function") violations.push(`line ${at}: new Function()`);
    if (ts.isPropertyAccessExpression(node) && node.name.text === "mainModule" && ts.isIdentifier(node.expression) && node.expression.text === "process") violations.push(`line ${at}: process.mainModule`);
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return violations;
}

/** Names that give, or can manufacture, module access or code evaluation. In security-sensitive tooling they may not appear at all:
 * not as an identifier, a property name, a destructured name, a string literal or a template piece. `Reflect` is here because
 * `Reflect.apply/get/construct` invoke or reach a banned name without writing it as a call. */
export const INDIRECTION_NAMES: ReadonlySet<string> = new Set(["require", "createRequire", "eval", "Function", "globalThis", "global", "module", "mainModule",
  "constructor", "__proto__", "Reflect", "Proxy"]);
/** The only `process.<name>` members the reviewed tooling uses. Any other member, and any use of `process` that is not `process.<one of these>`
 * (destructuring, aliasing, passing it on, `process["x"]`, `process[key]`), is a violation. */
export const PROCESS_MEMBERS_ALLOWED: ReadonlySet<string> = new Set(["argv", "cwd", "env", "execPath", "exitCode", "getuid", "platform", "stderr", "stdout"]);
/** Node built-ins that evaluate code, load modules or expose `process` under another name. Child processes are NOT here: the spawn sites are
 * pinned separately by tests/r06-activation-hygiene.test.ts. */
export const FORBIDDEN_NODE_MODULES: ReadonlySet<string> = new Set(["vm", "module", "worker_threads", "inspector", "repl", "process", "v8", "cluster", "wasi"]);

/** F2: indirect module/code access in security-sensitive tooling. See the header comment, item 4. */
export function indirectAccessViolations(source: string, fileName = "source.ts"): string[] {
  const sourceFile = parseSource(source, fileName);
  const violations: string[] = [];
  const add = (node: ts.Node, message: string) => violations.push(`line ${sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1}: ${message}`);
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node)) {
      if (INDIRECTION_NAMES.has(node.text)) add(node, `\`${node.text}\` must not appear in security-sensitive tooling`);
      if (node.text === "process") {
        const parent = node.parent;
        const member = ts.isPropertyAccessExpression(parent) && parent.expression === node ? parent.name.text : null;
        const propertyNameOfOther = ts.isPropertyAccessExpression(parent) && parent.name === node;
        if (!propertyNameOfOther && (member === null || !PROCESS_MEMBERS_ALLOWED.has(member)))
          add(node, `\`process\` may only be used as process.<${[...PROCESS_MEMBERS_ALLOWED].join("|")}>; found \`${parent.getText(sourceFile).slice(0, 50)}\``);
      }
    }
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
      if (INDIRECTION_NAMES.has(node.text.trim())) add(node, `the string "${node.text.trim()}" must not appear in security-sensitive tooling (a computed property name could use it)`);
    }
    if (ts.isMetaProperty(node) && node.keywordToken === ts.SyntaxKind.ImportKeyword) {
      const parent = node.parent;
      if (!(ts.isPropertyAccessExpression(parent) && parent.expression === node && parent.name.text === "url")) add(node, "import.meta may only be used as import.meta.url");
    }
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const direct = ts.isIdentifier(callee) || ts.isPropertyAccessExpression(callee) || callee.kind === ts.SyntaxKind.ImportKeyword || callee.kind === ts.SyntaxKind.SuperKeyword;
      if (!direct) add(node, `indirect invocation \`${callee.getText(sourceFile).slice(0, 40)}(...)\`: a callee must be an identifier or a property access`);
    }
    if (ts.isNewExpression(node) && !(ts.isIdentifier(node.expression) || ts.isPropertyAccessExpression(node.expression)))
      add(node, `indirect construction \`new ${node.expression.getText(sourceFile).slice(0, 40)}\``);
    if (ts.isTaggedTemplateExpression(node) && !(ts.isIdentifier(node.tag) || ts.isPropertyAccessExpression(node.tag))) add(node, "indirect tagged template");
    if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression) && HOST_OBJECTS.has(node.expression.text)) add(node, `computed access on ${node.expression.text}`);
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return violations;
}

/** F2: imports of Node built-ins that evaluate code or load modules, however spelled (`node:vm`, `vm`, `node:module`, ...). */
export function forbiddenNodeModuleViolations(source: string, fileName = "source.ts"): string[] {
  return collectModuleReferences(source, fileName).filter((reference) => reference.specifier !== null &&
    FORBIDDEN_NODE_MODULES.has(reference.specifier.replace(/^node:/u, "").split("/")[0]))
    .map((reference) => `line ${reference.line}: ${reference.kind} of ${reference.specifier}`);
}

// ---------------------------------------------------------------------------
// Finding 2: STRUCTURAL child-process and network enforcement
// ---------------------------------------------------------------------------
//
// These replace the earlier plain-text belts (regular expressions over comment-stripped lines, which `/**/ fetch(...)`, a namespace import
// or an aliased `spawnSync` walked straight past). Everything below reads the syntax tree: comments and trivia do not exist in it, and an
// alias, a namespace, a destructuring or an extra call is a different tree shape, not a different string.

/** Node built-ins and packages that open a socket, resolve names, or are a provider client/SDK. R06 tooling is local-only: none may be
 * referenced in ANY form (static, dynamic with a literal, require, import-equals, re-export, type import). `dns/promises`, `node:`-prefixed
 * spellings reduce to the first path segment (scope included) below. */
export const FORBIDDEN_NETWORK_MODULES: ReadonlySet<string> = new Set(["net", "http", "https", "http2", "tls", "dns", "dgram", "quic",
  "undici", "ws", "axios", "node-fetch", "cross-fetch", "got", "ky", "superagent", "request", "needle", "socket.io-client",
  "cloudflare", "@cloudflare", "miniflare", "wrangler"]);
/** Global network clients (and the globals that would reach them). Banned as any identifier or property name in the tooling. */
export const FORBIDDEN_NETWORK_GLOBALS: ReadonlySet<string> = new Set(["fetch", "WebSocket", "XMLHttpRequest", "EventSource", "navigator", "self", "window", "Deno", "Bun"]);

const packageRoot = (specifier: string): string => {
  const bare = specifier.replace(/^node:/u, "").toLowerCase();
  const segments = bare.split("/");
  return bare.startsWith("@") ? segments.slice(0, 1).join("/") : segments[0];
};

/** F2 (finding 2): no network-capable built-in, client package or global client anywhere in the tree, whatever the comments say. */
export function networkCapabilityViolations(source: string, fileName = "source.ts"): string[] {
  const sourceFile = parseSource(source, fileName);
  const violations: string[] = [];
  const add = (node: ts.Node, message: string) => violations.push(`line ${sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1}: ${message}`);
  for (const reference of collectModuleReferences(source, fileName))
    if (reference.specifier !== null && FORBIDDEN_NETWORK_MODULES.has(packageRoot(reference.specifier))) violations.push(`line ${reference.line}: ${reference.kind} of network-capable module ${reference.specifier}`);
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && FORBIDDEN_NETWORK_GLOBALS.has(node.text)) add(node, `\`${node.text}\` (a global network client or a route to one) must not appear in R06 tooling`);
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && FORBIDDEN_NETWORK_GLOBALS.has(node.text.trim())) add(node, `the string "${node.text.trim()}" must not appear in R06 tooling (a computed property name could use it)`);
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return violations;
}

/** The ONE reviewed child-process use a tooling file may have: one named import, never aliased, called directly exactly `calls` times, with
 * these exact first and (whitespace-collapsed) second argument expressions. */
export type ChildProcessUse = { name: string; calls: number; firstArgument: string; secondArgument: string };
const isChildProcess = (specifier: string): boolean => packageRoot(specifier) === "child_process";

/** F2 (finding 2): `node:child_process` is forbidden unless `allowed` names the exact reviewed use. `allowed === null` means the file may not
 * reference it at all. Anything else -- a namespace or default import, an alias, a second symbol (exec, execFile, fork, spawn ...), a dynamic
 * import or require, a re-export, a reference that is not a direct call, an extra call site, a different argument -- is a violation. */
export function childProcessViolations(source: string, allowed: ChildProcessUse | null, fileName = "source.ts"): string[] {
  const sourceFile = parseSource(source, fileName);
  const violations: string[] = [];
  const at = (node: ts.Node) => sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
  const all = collectModuleReferences(source, fileName);
  // a computed or malformed specifier could be child_process under another spelling: it is never acceptable in R06 tooling
  for (const reference of all) if (reference.specifier === null) violations.push(`line ${reference.line}: ${reference.kind} with a computed or malformed specifier cannot be proven not to be child_process`);
  const references = all.filter((reference) => reference.specifier !== null && isChildProcess(reference.specifier));
  if (allowed === null) return [...violations, ...references.map((reference) => `line ${reference.line}: ${reference.kind} of child_process is not allowed in this file`)];
  if (references.length !== 1) violations.push(`expected exactly one child_process reference (the reviewed \`${allowed.name}\` import), found ${references.length}`);
  for (const reference of references) {
    if (reference.kind !== "import" || reference.shape !== "named" || reference.typeOnly) violations.push(`line ${reference.line}: ${reference.kind}/${reference.shape} of child_process (only a static named import of \`${allowed.name}\` is allowed)`);
    else if (reference.names.length !== 1 || reference.names[0] !== allowed.name) violations.push(`line ${reference.line}: child_process names [${reference.names.join(", ")}] differ from the reviewed [${allowed.name}]`);
  }
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || !isChildProcess(statement.moduleSpecifier.text)) continue;
    const bindings = statement.importClause?.namedBindings;
    if (bindings && ts.isNamedImports(bindings)) for (const element of bindings.elements) if (element.propertyName) violations.push(`line ${at(element)}: child_process import aliased (${element.propertyName.text} as ${element.name.text})`);
  }
  let calls = 0;
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === allowed.name) {
      calls += 1;
      const first = node.arguments[0]?.getText(sourceFile).replace(/\s+/gu, " ");
      const second = node.arguments[1]?.getText(sourceFile).replace(/\s+/gu, " ");
      if (first !== allowed.firstArgument) violations.push(`line ${at(node)}: ${allowed.name} first argument \`${first}\` differs from the reviewed \`${allowed.firstArgument}\``);
      if (second !== allowed.secondArgument) violations.push(`line ${at(node)}: ${allowed.name} second argument \`${second}\` differs from the reviewed \`${allowed.secondArgument}\``);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  if (calls !== allowed.calls) violations.push(`${allowed.name} is called ${calls} time(s); the reviewed number is ${allowed.calls}`);
  // every reference to the imported binding must be the callee of a direct call: never stored, passed, aliased, destructured or `.call`ed
  violations.push(...referencesOf(sourceFile, new Set([allowed.name]), (node) => matchesShape(node, { kind: "call" }), `${allowed.name} (child_process)`));
  return violations;
}

/** Every element access whose key is not a string or numeric literal, as `<expression>` text. Data-record lookups are legitimate, but each
 * one is a place where a computed name could become `constructor`/`__proto__`; the reviewed tooling pins the exact set (see the guard test). */
export function computedAccessSites(source: string, fileName = "source.ts"): string[] {
  const sourceFile = parseSource(source, fileName);
  const found: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isElementAccessExpression(node) && !(ts.isStringLiteral(node.argumentExpression) || ts.isNumericLiteral(node.argumentExpression) || ts.isNoSubstitutionTemplateLiteral(node.argumentExpression)))
      found.push(node.getText(sourceFile).replace(/\s+/gu, " "));
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return found.sort();
}

export type Shape = { kind: "call" } | { kind: "property"; name: string } | { kind: "method-call"; name: string };

/** For every LOCAL name bound by a named import of `importedName` from the module called `module`, requires each reference to have exactly
 * the syntactic shape given:
 *   call         the binding is only ever the callee of a call            `make(...)`
 *   property     the binding is only ever the object of `.name`           `BINDINGS.staging`
 *   method-call  the binding is only ever `.name(...)`'s object           `signer.ready(...)`
 * Aliased imports (`as`) are tracked by their local name. Any other reference -- passed, assigned, returned, spread, destructured,
 * element-accessed (`signer["sign"]`, `signer[key]`), or a different property -- is a violation. */
export function referenceShapeViolations(source: string, module: string, importedName: string, shape: Shape, fileName = "source.ts"): string[] {
  const sourceFile = parseSource(source, fileName);
  const locals = new Set<string>();
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || moduleName(statement.moduleSpecifier.text) !== module) continue;
    const bindings = statement.importClause?.namedBindings;
    if (bindings && ts.isNamedImports(bindings)) for (const element of bindings.elements) if ((element.propertyName ?? element.name).text === importedName) locals.add(element.name.text);
  }
  return referencesOf(sourceFile, locals, (node) => matchesShape(node, shape), `${importedName} (${module})`);
}

function matchesShape(node: ts.Identifier, shape: Shape): boolean {
  const parent = node.parent;
  if (shape.kind === "call") return ts.isCallExpression(parent) && parent.expression === node;
  if (shape.kind === "property") return ts.isPropertyAccessExpression(parent) && parent.expression === node && parent.name.text === shape.name;
  return ts.isPropertyAccessExpression(parent) && parent.expression === node && parent.name.text === shape.name
    && ts.isCallExpression(parent.parent) && parent.parent.expression === parent;
}

/** All identifiers in `locals`, other than the declaration sites in the import and the property-name positions of other objects. */
function referencesOf(sourceFile: ts.SourceFile, locals: ReadonlySet<string>, ok: (node: ts.Identifier) => boolean, label: string): string[] {
  const violations: string[] = [];
  if (locals.size === 0) return violations;
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && locals.has(node.text) && !isDeclarationOrNonReference(node)) {
      if (!ok(node)) violations.push(`line ${sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1}: ${label} is used as \`${node.parent.getText(sourceFile).slice(0, 60)}\`, which is not the one allowed use`);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return violations;
}

function isDeclarationOrNonReference(node: ts.Identifier): boolean {
  const parent = node.parent;
  if (ts.isImportSpecifier(parent) || ts.isImportClause(parent) || ts.isNamespaceImport(parent)) return true;
  // The declaration name of `const signer = ...` introduces the binding; it is not a use of it.
  if (ts.isVariableDeclaration(parent) && parent.name === node) return true;
  // `obj.name` -- the identifier is only a property NAME of another object, not a reference to the binding.
  if (ts.isPropertyAccessExpression(parent) && parent.name === node) return true;
  if ((ts.isPropertyAssignment(parent) || ts.isPropertySignature(parent) || ts.isMethodDeclaration(parent)) && parent.name === node) return true;
  return false;
}

/** The signer capability rule for key custody. The factory import must be used exactly as `const <v> = factory(...)`, and `<v>` exactly as
 * `<v>.<allowed>(...)`. So custody can invoke the readiness/self-test capability and nothing else of the signer: no `.sign`, however spelled. */
export function signerCapabilityViolations(source: string, options: { module: string; factory: string; allowedMethod: string; forbiddenName: string }, fileName = "source.ts"): string[] {
  const sourceFile = parseSource(source, fileName);
  const violations = referenceShapeViolations(source, options.module, options.factory, { kind: "call" }, fileName);
  const factoryLocals = new Set<string>();
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || moduleName(statement.moduleSpecifier.text) !== options.module) continue;
    const bindings = statement.importClause?.namedBindings;
    if (bindings && ts.isNamedImports(bindings)) for (const element of bindings.elements) if ((element.propertyName ?? element.name).text === options.factory) factoryLocals.add(element.name.text);
  }
  const signerVariables = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && factoryLocals.has(node.expression.text)) {
      const at = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
      const declaration = node.parent;
      if (ts.isVariableDeclaration(declaration) && declaration.initializer === node && ts.isIdentifier(declaration.name) &&
          ts.isVariableDeclarationList(declaration.parent) && (declaration.parent.flags & ts.NodeFlags.Const) !== 0) signerVariables.add(declaration.name.text);
      else violations.push(`line ${at}: the signer must be bound directly to a const (\`const signer = ${node.expression.text}(...)\`); chaining, destructuring or passing it on is not allowed`);
    }
    // The forbidden capability may not be NAMED anywhere in custody (identifier, property, string, computed key).
    if ((ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && node.text === options.forbiddenName) {
      violations.push(`line ${sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1}: \`${options.forbiddenName}\` must not appear in key custody`);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  violations.push(...referencesOf(sourceFile, signerVariables, (node) => matchesShape(node, { kind: "method-call", name: options.allowedMethod }), "the signer"));
  return violations;
}

// ---------------------------------------------------------------------------
// Repository scan
// ---------------------------------------------------------------------------

/**
 * The ONLY directories the repository scan does not enter, each by EXACT repository-relative path (never by basename, so a `dist`, `build`,
 * `out` or dot-directory anywhere else -- including `workers/dist` or `scripts/.hidden` -- IS scanned). Each one is generated or third-party
 * output that is not repository source and is not part of any reviewed commit:
 *   node_modules   third-party packages installed from package-lock.json (git-ignored)
 *   .git           the git object store and hooks (not working-tree source; hooks are not versioned)
 *   .next .npm-cache .wrangler artifacts out .playwright test-results playwright-report
 *                  build, cache, local-runtime and test-evidence output, all git-ignored in .gitignore (the guard test asserts each
 *                  excluded directory that exists is in fact ignored by git, so none of them can hold committed code)
 * Everything else, including every dot-directory such as `.github`, is scanned.
 */
export const SCAN_EXCLUDED_DIRECTORIES: readonly string[] = Object.freeze(["node_modules", ".git", ".next", ".npm-cache", ".wrangler", "artifacts", "out", ".playwright",
  "test-results", "playwright-report"]);
// Case-INSENSITIVE: a Windows/macOS loader resolves `./helper` to `Helper.TS`, so a file whose extension is spelled in upper case is still a script.
// Declaration files are scanned too: `import "./x.d"` loads and EXECUTES `x.d.ts` under tsx, so excluding them would hide an importer.
const SCRIPT_FILE = /\.(?:[cm]?ts|tsx|[cm]?js|jsx)$/iu;

/** Every script file under `root` (POSIX-relative paths) outside `SCAN_EXCLUDED_DIRECTORIES`. A symlink is an ERROR, not a skip: the scan
 * cannot prove where it leads, and a link into a directory of scripts would hide them from every guard that uses this scan. */
export async function listScriptFiles(root: string, directory = root): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    const rel = relative(root, path).replaceAll("\\", "/");
    if (SCAN_EXCLUDED_DIRECTORIES.includes(rel)) continue;
    if (entry.isSymbolicLink()) throw new Error(`repository scan: symlink ${rel} cannot be proven to lead nowhere unscanned`);
    if (entry.isDirectory()) out.push(...await listScriptFiles(root, path));
    else if (entry.isFile() && SCRIPT_FILE.test(entry.name)) out.push(rel);
    else if (!entry.isFile() && !entry.isDirectory()) throw new Error(`repository scan: ${rel} is neither a regular file nor a directory`);
  }
  return out.sort();
}

export type RepositoryReferences = Map<string, ModuleReference[]>;

export async function scanRepository(root: string): Promise<RepositoryReferences> {
  const map: RepositoryReferences = new Map();
  for (const file of await listScriptFiles(root)) map.set(file, collectModuleReferences(await readFile(join(root, file), "utf8"), file));
  return map;
}

/** A reference whose module cannot be proven (computed `import()`/`require()`, `createRequire`, an aliased or indirectly obtained
 * `require`, `module[...]`). It could name ANY module, including a guarded one, so it is reported -- never skipped. */
export type UnprovableReference = { file: string; kind: ReferenceKind; line: number };
export function unprovableReferences(references: RepositoryReferences): UnprovableReference[] {
  const out: UnprovableReference[] = [];
  for (const [file, list] of references) for (const entry of list) if (entry.specifier === null) out.push({ file, kind: entry.kind, line: entry.line });
  return out.sort((a, b) => (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1));
}

/** Fails closed: throws unless every unprovable reference in `references` is covered by `reviewed` (file -> the kinds it may contain, one
 * list entry per allowed occurrence). The exception table is reviewed by hand; a new file, a new kind, or one more occurrence than listed
 * is a failure. */
export function assertNoUnreviewedUnprovableReferences(references: RepositoryReferences, reviewed: Readonly<Record<string, readonly ReferenceKind[]>>): void {
  const used = new Map<string, number>();
  const offences: string[] = [];
  for (const entry of unprovableReferences(references)) {
    const key = `${entry.file}\0${entry.kind}`;
    const seen = (used.get(key) ?? 0) + 1;
    used.set(key, seen);
    const allowed = (reviewed[entry.file] ?? []).filter((kind) => kind === entry.kind).length;
    if (seen > allowed) offences.push(`${entry.file}:${entry.line} ${entry.kind} with a module that cannot be proven`);
  }
  if (offences.length) throw new Error(`repository scan cannot prove these module references (fail closed):\n${offences.join("\n")}`);
}

/** Files (relative paths) holding at least one reference, of ANY kind, to one of the named modules. This only sees PROVABLE references:
 * a caller must first prove there is no unreviewed unprovable one (`assertNoUnreviewedUnprovableReferences`), so a computed specifier
 * cannot hide a guarded import behind a skipped `null`. */
export function filesReferencing(references: RepositoryReferences, modules: readonly string[]): string[] {
  const wanted = new Set(modules);
  return [...references].filter(([, list]) => list.some((entry) => entry.specifier !== null && wanted.has(moduleName(entry.specifier)))).map(([file]) => file).sort();
}

/** Files that import `name` (statically, by its original name) from `module`, or reference `module` in any non-static way. */
export function filesImporting(references: RepositoryReferences, module: string, name: string): string[] {
  return [...references].filter(([, list]) => list.some((entry) => entry.specifier !== null && moduleName(entry.specifier) === module &&
    (entry.shape !== "named" || entry.names.includes(name)))).map(([file]) => file).sort();
}

// ---------------------------------------------------------------------------
// Finding 1: exact-file resolution of every reference to a protected module
// ---------------------------------------------------------------------------

const RESOLVE_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".jsx"] as const;

/** Resolves a RELATIVE or `@/` specifier written in `importer` (repository-relative, POSIX) to the repository file it names, by the same
 * probing the toolchain does (as written, then each script extension, then `.js`/`.mjs`/`.cjs` -> the TypeScript source, then
 * `index.*`) -- but against the EXACT-CASE list of repository files, so an alternate-case spelling that a case-insensitive file system
 * would accept finds nothing. Returns null for anything else (a bare package, a `file:` URL, an absolute path, a path leaving the
 * repository, a name that matches only case-insensitively). Pure: `files` is the set of repository script files. */
export function resolveRepositorySpecifier(importer: string, specifier: string, files: ReadonlySet<string>): string | null {
  const path = specifier;
  let base: string;
  if (path.startsWith("@/")) base = posix.normalize(`src/${path.slice(2)}`);
  else if (path.startsWith("./") || path.startsWith("../")) base = posix.normalize(posix.join(posix.dirname(importer), path));
  else return null;
  if (base.startsWith("../") || base === "..") return null;
  const candidates = [base, ...RESOLVE_EXTENSIONS.map((extension) => `${base}${extension}`)];
  const stripped = /^(.*)\.(?:js|mjs|cjs|jsx)$/u.exec(base);
  if (stripped) candidates.push(...[".ts", ".tsx", ".mts", ".cts"].map((extension) => `${stripped[1]}${extension}`));
  candidates.push(...RESOLVE_EXTENSIONS.map((extension) => `${base}/index${extension}`));
  return candidates.find((candidate) => files.has(candidate)) ?? null;
}

/**
 * The importer pin's input guard. `protectedModules` maps a CANONICAL module name (lower-case, see `moduleName`) to the one repository file
 * it must mean. For every reference in `references` (one importer's) whose canonical name is protected, ANY spelling that is not the plain
 * one is a violation, and the reference must resolve -- case-exactly -- to the intended file:
 *   - an alternate-case last segment or directory         (`Staging-Key`, resolved by a case-insensitive file system)
 *   - a specifier that resolves to some OTHER file, or to nothing the scan can see (a bare package of that name, a `file:` URL, an absolute
 *     path)
 * Percent-encoded, backslash, whitespace, `?` and `#` spellings never reach here: the collector reports them as unprovable (specifier null),
 * which the repository scan treats as a failure. Nothing here consults a TypeScript diagnostic: `// @ts-ignore` and untyped `.mjs`/`.cjs` files change nothing.
 */
export function protectedReferenceViolations(importer: string, references: readonly ModuleReference[], files: ReadonlySet<string>, protectedModules: Readonly<Record<string, string>>): string[] {
  const violations: string[] = [];
  for (const reference of references) {
    if (reference.specifier === null) continue;
    const canonical = moduleName(reference.specifier);
    const intended = Object.hasOwn(protectedModules, canonical) ? protectedModules[canonical] : undefined;
    if (intended === undefined) {
      // Belt on top of name attribution: whatever the last segment says, a reference that RESOLVES (case-exactly) to a protected file is a
      // reference to it. Under the accepted grammar the two cannot differ for a loadable spelling, so a difference is itself a finding.
      const alias = resolveRepositorySpecifier(importer, reference.specifier, files);
      if (alias !== null && Object.values(protectedModules).includes(alias))
        violations.push(`${importer}:${reference.line}: ${reference.kind} (${JSON.stringify(reference.specifier)}) resolves to protected file ${alias} under a name that is not its own`);
      continue;
    }
    const where = `${importer}:${reference.line}: ${reference.kind} of protected module ${canonical} (${JSON.stringify(reference.specifier)})`;
    const resolved = resolveRepositorySpecifier(importer, reference.specifier, files);
    if (resolved === null) violations.push(`${where} does not resolve case-exactly to a repository file`);
    else if (resolved !== intended) violations.push(`${where} resolves to ${resolved}, not ${intended}`);
  }
  return violations;
}

/** `protectedReferenceViolations` over the whole repository scan. Every protected file must exist, or the table itself is stale. */
export function repositoryProtectedReferenceViolations(references: RepositoryReferences, protectedModules: Readonly<Record<string, string>>): string[] {
  const files = new Set(references.keys());
  const violations = Object.entries(protectedModules).filter(([, file]) => !files.has(file)).map(([name, file]) => `protected module ${name} -> ${file} is not a scanned repository file`);
  for (const [importer, list] of references) violations.push(...protectedReferenceViolations(importer, list, files, protectedModules));
  return violations;
}

// ---------------------------------------------------------------------------
// Fifth-audit remediation: traversal, package names, and the alias surface
// ---------------------------------------------------------------------------

/** Relative and `@/` specifiers (any importer) whose path leaves the repository. A protected file lives inside it, so such a spelling can
 * only be a way around exact-file resolution. */
export function escapingReferenceViolations(importer: string, references: readonly ModuleReference[]): string[] {
  const out: string[] = [];
  for (const reference of references) {
    if (reference.specifier === null) continue;
    const path = reference.specifier;
    const kind = classifySpecifierPath(path);
    let base: string | null = null;
    if (kind === "relative") base = posix.normalize(posix.join(posix.dirname(importer), path));
    else if (kind === "alias") base = posix.normalize(`src/${path.slice(2)}`);
    if (base !== null && (base === ".." || base.startsWith("../"))) out.push(`${importer}:${reference.line}: ${JSON.stringify(reference.specifier)} leaves the repository`);
  }
  return out;
}

/** Every package specifier must name a declared dependency, a Node built-in spelled without `node:`, or an explicitly reviewed exception. A
 * bare specifier that is none of those could only resolve through an alias (tsconfig `paths`, package.json `imports`, a symlink) and is refused. */
export function unknownPackageViolations(references: RepositoryReferences, declared: ReadonlySet<string>, builtins: ReadonlySet<string>, reviewedExceptions: ReadonlySet<string>): string[] {
  const out: string[] = [];
  for (const [file, list] of references) for (const reference of list) {
    if (reference.specifier === null) continue;
    const path = reference.specifier;
    if (classifySpecifierPath(path) !== "package") continue;
    const segments = path.split("/");
    const name = path.startsWith("@") ? segments.slice(0, 2).join("/") : segments[0];
    if (!declared.has(name) && !builtins.has(name) && !reviewedExceptions.has(name)) out.push(`${file}:${reference.line}: package ${JSON.stringify(name)} is neither a declared dependency, a Node built-in nor a reviewed exception`);
  }
  return out.sort();
}

/** The reviewed alias surface of this repository, as text. package.json may not remap specifiers (`imports`, or `exports` for self-reference);
 * tsconfig.json may map exactly `@/*` -> `./src/*` and nothing else (no `baseUrl`, `rootDirs`, `extends`, extra `paths`). tsx and TypeScript honour
 * every one of these, so each is a way to load a protected module under a name nobody attributes. */
export function aliasSurfaceViolations(packageJson: string, tsconfig: string): string[] {
  const out: string[] = [];
  let manifest: unknown;
  try { manifest = JSON.parse(packageJson); } catch { return ["package.json is not valid JSON"]; }
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) return ["package.json is not an object"];
  for (const field of ["imports", "exports"]) if (Object.hasOwn(manifest, field)) out.push(`package.json defines "${field}" (a specifier alias surface)`);
  const parsed = ts.parseConfigFileTextToJson("tsconfig.json", tsconfig);
  if (parsed.error || parsed.config === null || typeof parsed.config !== "object") return [...out, "tsconfig.json cannot be parsed"];
  const config = parsed.config as { extends?: unknown; compilerOptions?: Record<string, unknown>; references?: unknown };
  if (Object.hasOwn(config, "extends")) out.push("tsconfig.json extends another configuration");
  const options = config.compilerOptions ?? {};
  for (const option of ["baseUrl", "rootDirs"]) if (Object.hasOwn(options, option)) out.push(`tsconfig.json sets compilerOptions.${option}`);
  if (JSON.stringify(options.paths) !== JSON.stringify({ "@/*": ["./src/*"] })) out.push(`tsconfig.json compilerOptions.paths is not exactly {"@/*":["./src/*"]}`);
  return out;
}

/** Every file that could carry such an alias (package.json, tsconfig*.json, jsconfig*.json) anywhere outside the excluded directories. */
export async function aliasConfigFiles(root: string, directory = root): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    const rel = relative(root, path).replaceAll("\\", "/");
    if (SCAN_EXCLUDED_DIRECTORIES.includes(rel)) continue;
    if (entry.isSymbolicLink()) throw new Error(`alias scan: symlink ${rel} cannot be proven to lead nowhere unscanned`);
    if (entry.isDirectory()) out.push(...await aliasConfigFiles(root, path));
    else if (/^(?:package|tsconfig(?:..*)?|jsconfig(?:..*)?).json$/iu.test(entry.name)) out.push(rel);
  }
  return out.sort();
}
