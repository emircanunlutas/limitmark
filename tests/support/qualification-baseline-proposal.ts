import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { REVIEWED_PATCHES } from "./reviewed-patches";

// READ-ONLY proposal generator for "qualification baseline v2" (see QUALIFICATION-BASELINE-MIGRATION-PROPOSAL.md). It reads git history and the working
// tree and prints a deterministic JSON register to stdout. It writes nothing, changes no test and re-pins nothing: the register it prints is a PROPOSAL until
// a separate review accepts it. Fail closed: a drifted path that is not explicitly classified below aborts (exit 2) instead of being auto-classified.
//   tsx tests/support/qualification-baseline-proposal.ts [baselineCommit]
// Lives in tests/support on purpose: it references lab paths and the reviewed-patch registry, which no runtime/script file may.

const BASELINE = process.argv[2] ?? "dcf10af8229a5738b1852721fe12de86a488d07d";
const SCOPE = ["defense", "src", "workers", "lab/policy", "lab/defense/salvo-spec.ts", "lab/defense/salvo-reconcile.ts", "lab/defense/reconcile.ts", "lab/defense/field-verdict.ts",
  "lab/defense/n2-measurement.ts", "lab/defense/external-reducer.ts", "lab/defense/external-accounting.ts", "lab/defense/canary.ts", "lab/defense/field-canary.ts", "lab/defense/collector.ts",
  "lab/defense/exposure-proof.ts", "lab/evidence"];

type Category = "PRODUCTION_PREPARATION" | "GATE_11A_GUARD_EXPORT" | "LABORATORY" | "OBSERVABILITY" | "SHARED_FIX";
/** Explicit, human-reviewed classification. `securityNote` records review findings; "none" means the diff was read and no weakening was found. */
const CLASSIFICATION: Record<string, { category: Category; securityNote: string }> = {
  "src/app/api/public-inquiries/route.ts": { category: "PRODUCTION_PREPARATION", securityNote: "none: production branch delegates to the factory; disabled => generic 503" },
  "src/lib/admission-client.server.ts": { category: "PRODUCTION_PREPARATION", securityNote: "none: additive Vercel OIDC provider (request-scoped, timeout, pending cap, claim checks); lab Google provider is a separate class" },
  "src/lib/public-inquiry-production-runtime.server.ts": { category: "PRODUCTION_PREPARATION", securityNote: "none: refuses LAB_/GOOGLE_/LIMITMARK_RUNTIME, verified-TLS and telemetry-off launch policy" },
  "src/lib/production-launch-policy.ts": { category: "PRODUCTION_PREPARATION", securityNote: "none: new, fail-closed" },
  "workers/admission-service/index.ts": { category: "PRODUCTION_PREPARATION", securityNote: "O-2 ADDRESSED in 655d58a: the production deployment now builds from workers/admission-service/production-index.ts, which exports no lab or staging class; this shared module still exports them for the staging and lab entries" },
  "workers/admission-service/production-index.ts": { category: "PRODUCTION_PREPARATION", securityNote: "none: new (655d58a); re-exports only production names, pinned by tests/production-identity-contract.test.ts" },
  "workers/admin-gateway/index.ts": { category: "PRODUCTION_PREPARATION", securityNote: "none: removes non-handler re-exports so the bundle loads in workerd" },
  "workers/shared/bounded-jwks.ts": { category: "SHARED_FIX", securityNote: "none: wraps native fetch as a plain function; no verification change" },
  "workers/lifecycle-mailbox/dispatch-guard.ts": { category: "GATE_11A_GUARD_EXPORT", securityNote: "none: one SELECT-only, operator-authenticated method added; dispatch/settle code untouched" },
  "workers/lifecycle-mailbox/guard-export.ts": { category: "GATE_11A_GUARD_EXPORT", securityNote: "none: new request/response format" },
  "workers/lifecycle-mailbox/guard-reader.ts": { category: "GATE_11A_GUARD_EXPORT", securityNote: "none: single-method read-only entrypoint" },
  "workers/lifecycle-mailbox/index.ts": { category: "GATE_11A_GUARD_EXPORT", securityNote: "none: one additional entrypoint export" },
  "workers/lifecycle-observer.ts": { category: "GATE_11A_GUARD_EXPORT", securityNote: "none: optional relay of an authenticated read-only export; no new write path to the request bucket" },
  "src/lib/ingress-protocol.ts": { category: "LABORATORY", securityNote: "none for production: parser also accepts the lab environment tag; the production verifier still requires the production tag" },
  "src/lib/ingress-verifier.server.ts": { category: "LABORATORY", securityNote: "none for production: URL-authority comparison preserved unless policy.environment is the lab; policy is server configuration" },
  "src/lib/public-origin.ts": { category: "LABORATORY", securityNote: "none: lab branch selected only by LIMITMARK_RUNTIME; production VERCEL checks preserved (order of two failing checks changed, same outcome). OBSERVATION O-3" },
  "src/lib/public-inquiry-handler.server.ts": { category: "LABORATORY", securityNote: "none for production: production hostname/Origin/VERCEL checks preserved; OBSERVATION O-3; also carries telemetry wrapper (OBSERVABILITY)" },
  "src/lib/public-inquiry-runtime.server.ts": { category: "LABORATORY", securityNote: "none: new lab runtime factory" },
  "src/lib/db/database.server.ts": { category: "LABORATORY", securityNote: "none: optional verified-TLS object for the lab; production client options unchanged (see production-launch-policy)" },
  "src/app/test-talep-et/page.tsx": { category: "LABORATORY", securityNote: "none" },
  "src/proxy.ts": { category: "LABORATORY", securityNote: "none" },
  "src/lib/authority-result-attestation.ts": { category: "LABORATORY", securityNote: "none: adds the lab environment tag" },
  "src/lib/authority-result-trust.ts": { category: "LABORATORY", securityNote: "none: adds the lab environment section handling" },
  "workers/admission-service/auth.ts": { category: "LABORATORY", securityNote: "none: additive Google OIDC verifier; Vercel verifier untouched" },
  "workers/admission-service/service.ts": { category: "LABORATORY", securityNote: "none: authentication step parameterized; same checks and order for the Vercel path" },
  "workers/admission-service/authority.ts": { category: "LABORATORY", securityNote: "none: lab identity bound both ways" },
  "workers/admission-service/authority-attestation.ts": { category: "LABORATORY", securityNote: "none" },
  "workers/admission-service/authority-attestation-config.ts": { category: "LABORATORY", securityNote: "none" },
  "workers/admission-service/authority-attestation-signer.ts": { category: "LABORATORY", securityNote: "none" },
  "workers/admission-service/operator-command.ts": { category: "LABORATORY", securityNote: "none: lab environment/authority pairing added; production pairing unchanged" },
  "workers/admission-service/lab-index.ts": { category: "LABORATORY", securityNote: "none" },
  "workers/ingress-signer/google-id-token.ts": { category: "LABORATORY", securityNote: "none" },
  "workers/ingress-signer/index.ts": { category: "LABORATORY", securityNote: "none: adds originHostname" },
  "workers/ingress-signer/laboratory-index.ts": { category: "LABORATORY", securityNote: "none" },
  "workers/ingress-signer/signer.ts": { category: "LABORATORY", securityNote: "F-1 CORRECTED in 1720e9f: createIngressSigner again refuses any collision among the four secrets (production includes vercelBypassSecret); direct-caller regression tests added. Remaining drift is the lab environment tag" },
  "workers/lab-lifecycle-observer.ts": { category: "LABORATORY", securityNote: "none" },
  "workers/lab-operator-lifecycle-executor.ts": { category: "LABORATORY", securityNote: "none" },
  "workers/lifecycle-mailbox/lab-dispatch-guard.ts": { category: "LABORATORY", securityNote: "none" },
  "workers/lifecycle-mailbox/lab-index.ts": { category: "LABORATORY", securityNote: "none" },
  "workers/lifecycle-mailbox/lab-processor.ts": { category: "LABORATORY", securityNote: "none" },
  "src/lib/public-inquiry-otel.server.ts": { category: "OBSERVABILITY", securityNote: "none: inert unless PUBLIC_INQUIRY_OTEL_METRICS=true; production launch policy forbids it" },
  "src/lib/public-inquiry-telemetry.server.ts": { category: "OBSERVABILITY", securityNote: "none: bounded counters; never affects the response path" },
};

const git = (...args: string[]) => execFileSync("git", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] }).trim();
const sha256Lf = (text: string) => createHash("sha256").update(text.replace(/\r\n/gu, "\n")).digest("hex");
const reviewed = new Set(REVIEWED_PATCHES.map((patch) => patch.path));

const changed = git("diff", "--name-only", BASELINE, "--", ...SCOPE).split("\n").filter(Boolean).sort();
const entries: unknown[] = [];
const unclassified: string[] = [];
for (const path of changed) {
  if (reviewed.has(path)) continue;                                  // already covered by the P0-01/P0-02 reviewed-patch registry
  const classification = CLASSIFICATION[path];
  if (!classification) { unclassified.push(path); continue; }
  const baselineBlob = (() => { try { return git("rev-parse", `${BASELINE}:${path}`); } catch { return null; } })();   // null: file did not exist at the baseline (added)
  const commits = git("log", "--format=%h", `${BASELINE}..HEAD`, "--", path).split("\n").filter(Boolean).reverse();
  entries.push({ path, change: baselineBlob === null ? "added" : "modified", historicalBlob: baselineBlob, reviewedSha256: sha256Lf(readFileSync(path, "utf8")), commits,
    category: classification.category, securityNote: classification.securityNote });
}
if (unclassified.length > 0) {
  process.stderr.write(`Baseline proposal: REFUSED. Unclassified drifted path(s) -- classify them explicitly after review:\n${unclassified.map((path) => `  ${path}`).join("\n")}\n`);
  process.exitCode = 2;
} else {
  const body = { format: "limitmark-qualification-baseline-proposal-v2", status: "PROPOSED-NOT-ACCEPTED", historicalBaseline: BASELINE, head: git("rev-parse", "HEAD"),
    alreadyCoveredByReviewedPatchRegistry: [...reviewed].sort(), entries };
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
}
