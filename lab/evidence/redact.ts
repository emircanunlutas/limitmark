/**
 * Evidence safety scanner. The manifest writer refuses (throws) instead of "cleaning":
 * a refused write means a tool tried to record something it must never record, which is
 * a bug to fix at the source, not to mask. Free text that cannot be refused without losing the run
 * (error messages, raw child-process output) goes through `evidenceSafeError` / `sanitizeLog` BEFORE it is persisted:
 * the unsafe part is withheld, never written. `.gitignore` is not a confidentiality boundary and is not relied on.
 *
 * Never recorded: credentials, authorization headers, cookies (any name), raw IP identities (IPv4 and IPv6, also when
 * glued to a timestamp), URLs (any, and in particular any query string), request bodies / user data, DB URLs with
 * passwords, private keys, JWTs, stack traces and filesystem paths. Object KEYS are scanned like values.
 */

const FORBIDDEN_KEY_FRAGMENTS = [
  "authorization", "cookie", "password", "passwd", "secret", "apikey", "credential", "privatekey",
  "token", "bearer", "body", "payload", "forwarded", "clientip", "remoteaddr", "remoteaddress",
  "connectionstring", "databaseurl", "dsn", "email",
] as const;

/** Keys that are exactly an IP-identity carrier regardless of value. */
const FORBIDDEN_EXACT_KEYS = new Set(["ip", "ips", "address", "addresses", "headers", "header", "host", "hostname", "origin", "url", "uri"]);

/** Object keys are labels (metric names, outcome categories, error codes, HTTP statuses), never free text. */
const SAFE_KEY = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

const VALUE_PATTERNS: readonly [string, RegExp][] = [
  ["bearer-credential", /\bBearer\s+[A-Za-z0-9._~+/=-]{6,}/i],
  ["basic-credential", /\bBasic\s+[A-Za-z0-9+/=]{8,}/],
  ["url-with-credentials", /[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@/i],
  ["jwt", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/],
  ["private-key", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ["aws-access-key", /\bAKIA[0-9A-Z]{16}\b/],
  ["provider-api-key", /\b(re_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}|ghp_[A-Za-z0-9]{30,})\b/],
  // Any URL at all: a lab artifact has no reason to carry one, and a URL is where query-string credentials live.
  ["url", /(?:^|[^A-Za-z0-9])[A-Za-z][A-Za-z0-9+.-]{1,20}:\/\/\S/],
  // A query string anywhere (`/path?token=...`, `a=b&c=d`), with or without a scheme.
  ["query-string", /[?&][A-Za-z0-9_.~%-]{1,64}=/],
  // HTTP header carriers.
  ["cookie-header", /\b(?:set-)?cookie\s*:/i],
  ["authorization-header", /\b(?:proxy-)?authorization\s*:/i],
  // Cookies GENERICALLY: any `name=value` pair, whatever the name (session ids are not only called "session").
  // The pair may follow any non-name character: quotes, brackets and parentheses included.
  ["name-value-pair", /(?:^|[^A-Za-z0-9_.-])[A-Za-z_][A-Za-z0-9_.-]{0,63}=[^\s;,]+/],
  // `password: x`, `token = x`, `sid:x`: a secret-looking label followed by a value, with a colon or spaced equals sign.
  ["secret-assignment", /\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|session(?:[_-]?id)?|sid)\b\s*[:=]\s*\S/i],
  // Percent-escapes hide names and values from every other rule (`%73id=...`); evidence has no reason to carry them.
  ["percent-escape", /%[0-9A-Fa-f]{2}/],
  // IPv4 spelled as one decimal or hex number.
  ["numeric-ipv4", /(?<![0-9A-Za-z])(?:\d{9,10}|0[xX][0-9A-Fa-f]{8})(?![0-9A-Za-z])/],
  ["email-address", /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/],
  ["stack-trace", /(?:^|\n)\s+at\s+\S+|\bat\s+\S+\s+\((?:[A-Za-z]:\\|\/|file:|node:)|\bnode:internal\//],
  ["filesystem-path", /(?:[A-Za-z]:\\(?:Users|Documents and Settings|Windows|Program)|\/(?:home|Users|root|etc|var|tmp)\/)/],
];

const IPV4 = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d]|\.\d)/;
const IPV6 = /(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])/;
/** Well-formed instants are removed BEFORE the IPv6 scan; nothing else gets an exemption. */
const ISO_INSTANT = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g;
/** A bare HH:MM:SS(.fff) token: three groups, not a valid IPv6 spelling (which needs `::` or eight groups). */
const CLOCK_TIME = /(?<![0-9A-Fa-f:.])\d{2}:\d{2}:\d{2}(?:\.\d+)?(?![0-9A-Fa-f:.])/g;

export class EvidenceViolation extends Error {
  constructor(readonly path: string, readonly rule: string) {
    super(`evidence refused at ${path}: ${rule}`);
    this.name = "EvidenceViolation";
  }
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

const NO_EXEMPTIONS: ReadonlySet<string> = new Set();

/** The first rule a string breaks, or null. Pure; shared by the refusing scanner and the log/error sanitizers. */
export function findViolation(value: string, relaxedVersionField = false, exempt: ReadonlySet<string> = NO_EXEMPTIONS): string | null {
  // Only printable ASCII (plus newline/tab) is evidence: full-width digits, zero-width joiners and look-alike separators are how a
  // value is made to slip past every pattern below.
  if (!/^[\x09\x0a\x20-\x7e]*$/.test(value)) return "non-ascii-or-control-character";
  // An exempt rule is skipped, NOT treated as the answer: a line that matches an exempt rule must still be checked against every other one.
  for (const [rule, pattern] of VALUE_PATTERNS) if (!exempt.has(rule) && pattern.test(value)) return rule;
  if (!relaxedVersionField) {
    if (IPV4.test(value)) return "raw IPv4 address";
    const withoutTimes = value.replace(ISO_INSTANT, " ").replace(CLOCK_TIME, " ");
    if (IPV6.test(withoutTimes)) return "raw IPv6 address";
  }
  return null;
}

function scanString(path: string, key: string, value: string, relaxedVersionField: boolean): void {
  if (value.length > 512) throw new EvidenceViolation(path, "string longer than 512 characters");
  const violation = findViolation(value, relaxedVersionField);
  if (violation) throw new EvidenceViolation(path, violation);
  const normalized = normalizeKey(key);
  if (/^[0-9a-f]{64}$/.test(value) && !normalized.endsWith("sha256")) throw new EvidenceViolation(path, "64-hex value outside a sha256 field (possible secret)");
  if (/^[0-9a-f]{40}$/.test(value) && normalized !== "gitsha") throw new EvidenceViolation(path, "40-hex value outside gitSha");
  // Run ids are generated by EvidenceRun (timestamp-label-random) and are the one long identifier we emit.
  if (/^[A-Za-z0-9_+/=-]{32,}$/.test(value) && !/^[0-9a-f]{40,64}$/.test(value) && normalized !== "runid") throw new EvidenceViolation(path, "long token-like string");
}

/**
 * Walks a JSON-like value. `environment` (collector-built) may contain dotted version strings that
 * look like IPv4 (e.g. a kernel release), so IP detection is relaxed there only; every other rule applies.
 */
export function assertEvidenceSafe(value: unknown, path = "$", relaxedVersionField = false): void {
  if (value === null || typeof value === "number" || typeof value === "boolean") return;
  if (typeof value === "string") { scanString(path, path.split(".").pop() ?? "", value, relaxedVersionField); return; }
  if (Array.isArray(value)) { value.forEach((child, index) => assertEvidenceSafe(child, `${path}[${index}]`, relaxedVersionField)); return; }
  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const normalized = normalizeKey(key);
      const childPath = `${path}.${key}`;
      if (FORBIDDEN_EXACT_KEYS.has(normalized)) throw new EvidenceViolation(childPath, "forbidden key");
      if (FORBIDDEN_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment))) throw new EvidenceViolation(childPath, "forbidden key");
      // Keys are data too: an IP, a URL, a token or a path can hide in a key just as well as in a value.
      if (!SAFE_KEY.test(key)) throw new EvidenceViolation(childPath, "object key is not a plain label");
      const inRelaxedField = relaxedVersionField || (path === "$" && key === "environment");
      // Keys are never version strings, so the dotted-quad relaxation of the `environment` VALUES does not apply to them.
      const keyViolation = findViolation(key, false);
      if (keyViolation) throw new EvidenceViolation(childPath, `object key: ${keyViolation}`);
      // A long label is fine (camelCase metric names); a hex string or a long digit-rich string is a token, not a label.
      if (/^[0-9a-f]{32,}$/i.test(key) || (key.length >= 24 && (key.match(/\d/g) ?? []).length >= 4)) throw new EvidenceViolation(childPath, "object key looks like a token");
      assertEvidenceSafe(child, childPath, inRelaxedField);
    }
    return;
  }
  throw new EvidenceViolation(path, `unsupported value type ${typeof value}`);
}

/**
 * An error rendered for evidence: its class and code, and its message only when the message itself is evidence-safe.
 * Never the stack, never a message that could carry a URL, credential, address, path or free text of unknown origin.
 */
export function evidenceSafeError(error: unknown): string {
  const name = error instanceof Error ? (error.name.replace(/[^A-Za-z0-9_]/g, "").slice(0, 40) || "Error") : "NonError";
  const code = (error as { code?: unknown } | null)?.code;
  const codePart = typeof code === "string" && /^[A-Z0-9_]{3,40}$/.test(code) ? ` ${code}` : "";
  const message = error instanceof Error ? error.message : "";
  const printable = /^[\x20-\x7e]*$/.test(message) && message.length <= 200;
  if (!message || (printable && findViolation(message) === null && !/[0-9a-f]{32,}/i.test(message))) return message ? `${name}${codePart}: ${message}` : `${name}${codePart}`;
  return `${name}${codePart}: message withheld (not evidence-safe)`;
}

export type SanitizedLog = { text: string; lines: number; withheldLines: number; rules: Record<string, number> };

const HOME_PREFIXES: readonly RegExp[] = [/[A-Za-z]:\\Users\\[^\\\s]+/g, /\/(?:home|Users)\/[^/\s]+/g, /\/root\b/g];
const ANSI = /\u001b\[[0-9;]*[A-Za-z]/g;
/** `file.ts:12:34` and `location: '...:299:1'` look like two-group IPv6 to the scanner; the numbers are replaced (a position is no diagnostic worth a rule). */
const SOURCE_POSITION = /:\d+:\d+(?=[)\s'",]|$)/g;
/** A stack frame and a (home-rewritten) path are routine in test output; EVERY other rule still applies to such a line. */
const LOG_EXEMPT: ReadonlySet<string> = new Set(["stack-trace", "filesystem-path"]);
const MAX_LOG_LINE = 400;
const TRUNCATED = " [truncated]";

/** The one rule a log line breaks, or null. The SAME function decides what is written and verifies what was written. */
function logLineRule(line: string): string | null {
  const violation = findViolation(line, false, LOG_EXEMPT);
  if (violation) return violation;
  // Long runs of token-like characters (integrity hashes, keys) are withheld as a rule of their own.
  return /[A-Za-z0-9_+/=-]{40,}/.test(line) ? "long token-like string" : null;
}

function normalizeLogLine(original: string): string {
  let line = original.replace(ANSI, "");
  for (const prefix of HOME_PREFIXES) line = line.replace(prefix, "<home>");
  line = line.replace(/file:\/\/\/?/g, "<file>/").replace(SOURCE_POSITION, ":L:C");
  // Idempotent: a line already at the truncated length (400 + marker) is left alone.
  return line.length > MAX_LOG_LINE + TRUNCATED.length ? `${line.slice(0, MAX_LOG_LINE)}${TRUNCATED}` : line;
}

/**
 * Raw child-process / container output is NEVER persisted verbatim. Each line is normalized (ANSI removed, home directories
 * rewritten, file:// and source positions neutralized, long lines truncated) and the NORMALIZED line is what is scanned and what is
 * kept: any line that breaks an evidence rule (credential, Bearer, URL, query string, cookie pair, IPv4/IPv6, e-mail, encoded or
 * non-ASCII look-alike, ...) is replaced by a marker naming the rule, stack-shaped lines included. Over-redaction is intended: a log
 * is diagnostics, never evidence of a secret.
 */
export function sanitizeLog(raw: string): SanitizedLog {
  const rules: Record<string, number> = {};
  let withheldLines = 0;
  const output: string[] = [];
  const lines = raw.replace(/\r\n/g, "\n").split("\n");
  // A trailing newline terminates the last line; it is not an extra empty line (keeps sanitizing idempotent).
  if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
  for (const original of lines) {
    const line = normalizeLogLine(original);
    const rule = logLineRule(line);
    if (rule) { withheldLines++; rules[rule] = (rules[rule] ?? 0) + 1; output.push(`[line withheld: ${rule}]`); continue; }
    output.push(line);
  }
  return { text: `${output.join("\n")}\n`, lines: lines.length, withheldLines, rules };
}

/** Final gate over the exact bytes about to be persisted: returns the first offending line's rule, or null when every line is acceptable. */
export function verifyLogText(text: string): string | null {
  if (!/^[\x09\x0a\x20-\x7e]*$/.test(text)) return "non-ascii-or-control-character";
  for (const line of text.split("\n")) {
    if (line.length > MAX_LOG_LINE + TRUNCATED.length) return "over-long line";
    const rule = logLineRule(line);
    if (rule) return rule;
  }
  return null;
}
