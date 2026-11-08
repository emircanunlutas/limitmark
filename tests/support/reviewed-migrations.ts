import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { REVIEWED_PATCHES, withoutReviewedPatches } from "./reviewed-patches";

/**
 * Append-only, VERSIONED registry of reviewed changes to verdict-path files made after the historical baselines (64ccc9d, dcf10af8, aff793e).
 * It sits BESIDE tests/support/reviewed-patches.ts (which it does not alter) and follows the same two-halves rule:
 *
 *   historical half: at every baseline the file is the recorded blob (or absent, for an added file) -- no historical hash is replaced;
 *   reviewed half:   the working-tree file hashes (LF-normalized sha256) to the recorded value.
 *
 * Nothing is exempted unless its status is APPROVED. PENDING entries record evidence only: they are NOT excluded from any byte-identity diff, so
 * the historical tests keep failing for them until a human changes the status. Changing a status, adding an entry or changing a hash is a
 * reviewed act; entries are never deleted or silently re-hashed (a later edit to an APPROVED file fails the reviewed half until it is re-reviewed
 * and recorded as a NEW version). `hold` records why an entry is not yet a candidate for approval.
 */
export const MIGRATION_REGISTRY_VERSION = 1;
export const MIGRATION_BASELINES = [
  "64ccc9dabdde81fbc844807f8c104d707151de5e", "dcf10af8229a5738b1852721fe12de86a488d07d", "aff793e4968cd5615e25665c5437e20d268d744f",
] as const;

export type MigrationStatus = "PENDING" | "APPROVED";
export type MigrationHold = "none" | "shared-production-module" | "guard-export";
export type ReviewedMigration = {
  path: string;
  change: "added" | "modified";
  /** git blob id at every baseline, or null when the file is absent there (an added file). */
  historicalBlob: string | null;
  /** sha256 of the reviewed working-tree file, line endings normalized to LF. */
  reviewedSha256: string;
  reviewId: string;
  hold: MigrationHold;
  status: MigrationStatus;
};

export const REVIEWED_MIGRATIONS: readonly ReviewedMigration[] = Object.freeze([
  { path: "defense/core/outcome-counters.ts", change: "added", historicalBlob: null, reviewedSha256: "6169f8e5aacc78870345c60936bc2b3d58a02bfa954ac9ecf1c62fedaa0c6be8", reviewId: "INSTRUMENTATION/D1", hold: "none", status: "PENDING" },
  { path: "defense/plane/runtime.ts", change: "modified", historicalBlob: "5a909606d168e65d39f006d41cc5c2a798ad7e22", reviewedSha256: "d46cd98632bab52df42ce993b3862f4ee26cae4b889b02e9899ed798d205203c", reviewId: "INSTRUMENTATION/D1", hold: "none", status: "PENDING" },
  { path: "src/app/api/public-inquiries/route.ts", change: "modified", historicalBlob: "fb10855a51fd9fbf3d4765a54ba9339b22e3ad80", reviewedSha256: "d19fc52d41db601c7229e839040bf0e2802f07f61381236577156581155c2871", reviewId: "BASELINE-V2/PRODUCTION_PREPARATION", hold: "none", status: "PENDING" },
  { path: "src/app/test-talep-et/page.tsx", change: "modified", historicalBlob: "7dd22aa7763d51ab37441bf8ab0075edc3ad3133", reviewedSha256: "80e3a1d0d433143ba5f7b783ee66036f5e612cfaf47d0913e0e052713cd7a48b", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "src/lib/admission-client.server.ts", change: "modified", historicalBlob: "f8ea5e379791c620e59b9536da53588e12252e8d", reviewedSha256: "43582e2e9cb8be500269fa5509a74d1731e5705338b4fe70d4696bf1f47daf1d", reviewId: "BASELINE-V2/PRODUCTION_PREPARATION", hold: "none", status: "PENDING" },
  { path: "src/lib/authority-result-attestation.ts", change: "modified", historicalBlob: "d4aac6a6908dfb56a449fbfed715c7f74717ba56", reviewedSha256: "a5858c34d11f8f3a958f4c442037f0651e74d99aff95ff7ba11dedd8086bd1b9", reviewId: "BASELINE-V2/LABORATORY", hold: "shared-production-module", status: "PENDING" },
  { path: "src/lib/authority-result-trust.ts", change: "modified", historicalBlob: "8f784ee5b3cf5403a8d2f1b41567f402273478d1", reviewedSha256: "e232f0f1305999766c2fe4ea4ef96a64a33fbb57a1ffb5c3efedde57a4ee1ef9", reviewId: "BASELINE-V2/LABORATORY", hold: "shared-production-module", status: "PENDING" },
  { path: "src/lib/db/database.server.ts", change: "modified", historicalBlob: "f7b508c3cb27922316c4d1f6a7676230215f312f", reviewedSha256: "919202e113d8d437f015c6eaf96807bbe12e564be99be60a8005b29323ebf7d5", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "src/lib/ingress-protocol.ts", change: "modified", historicalBlob: "04de4ef57d95ccbc7fe9b523f6e85da861f39851", reviewedSha256: "6a7c17ef9e5b7f43d5448cfc69f44ab4f29320559458290f55c2bd1be9d9b3fa", reviewId: "BASELINE-V2/LABORATORY", hold: "shared-production-module", status: "PENDING" },
  { path: "src/lib/ingress-verifier.server.ts", change: "modified", historicalBlob: "cdd68bfa7580bbe6f76dbfc5e1d8ee470e93dfae", reviewedSha256: "3244951c85937ee83a046b4f88fd0e57e33d0c67e7bb6ddb47f19f405e3ef21f", reviewId: "BASELINE-V2/LABORATORY", hold: "shared-production-module", status: "PENDING" },
  { path: "src/lib/production-launch-policy.ts", change: "added", historicalBlob: null, reviewedSha256: "2b08e98a866ac13c2a6202096e620dce16f69a69e0c31c614b9087923d48f1fc", reviewId: "BASELINE-V2/PRODUCTION_PREPARATION", hold: "none", status: "PENDING" },
  { path: "src/lib/public-inquiry-handler.server.ts", change: "modified", historicalBlob: "d15207ff70d8ed431bd4735c6187f92ed2a2a35c", reviewedSha256: "9d06d12dcd80aba6f4a2dafe0880dbbbf4fd07fa1493e9c09c493329203406e0", reviewId: "BASELINE-V2/LABORATORY", hold: "shared-production-module", status: "PENDING" },
  { path: "src/lib/public-inquiry-otel.server.ts", change: "added", historicalBlob: null, reviewedSha256: "8c38cbb0244ead4b46ff367c88a5306bf8ce629c7298316948bf86d369375457", reviewId: "BASELINE-V2/OBSERVABILITY", hold: "none", status: "PENDING" },
  { path: "src/lib/public-inquiry-production-runtime.server.ts", change: "added", historicalBlob: null, reviewedSha256: "8b6680cfaf8bb6145ac6bbd2b6e1545465c7117656d481bcf320e726747bd7ed", reviewId: "BASELINE-V2/PRODUCTION_PREPARATION", hold: "none", status: "PENDING" },
  { path: "src/lib/public-inquiry-runtime.server.ts", change: "added", historicalBlob: null, reviewedSha256: "ed92d46c3c146f95ee2429d1cfa240b138fe8864cca89dd1c676e1a869a5c613", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "src/lib/public-inquiry-telemetry.server.ts", change: "added", historicalBlob: null, reviewedSha256: "3dcc5c8b286b3e0c4a29ea84fa7500366d5111df6ed2aff6e314ebc3cfd5a923", reviewId: "BASELINE-V2/OBSERVABILITY", hold: "none", status: "PENDING" },
  { path: "src/lib/public-origin.ts", change: "modified", historicalBlob: "3ca900726f0c77e52499ef5b46f0e6ffa8a9898e", reviewedSha256: "19673ef8351cea00d2cb5d16eb5542c8455a5c742d5783ec57cc948c91d57225", reviewId: "BASELINE-V2/LABORATORY", hold: "shared-production-module", status: "PENDING" },
  { path: "src/proxy.ts", change: "modified", historicalBlob: "dd18b5a02445bfccc893aaf85a9cac8a38687934", reviewedSha256: "3f77a95ac96cd04d78fb07b4315ec2a3c533fada36294650c77061917086bd7c", reviewId: "BASELINE-V2/LABORATORY", hold: "shared-production-module", status: "PENDING" },
  { path: "workers/admin-gateway/index.ts", change: "modified", historicalBlob: "98ea23e1764d2c504e7844bf5d300f6b2e4fee36", reviewedSha256: "a1c9e3061e46d25bf16727350a4664f9a94ba524076ef8ebe0d7bd684292f76e", reviewId: "BASELINE-V2/PRODUCTION_PREPARATION", hold: "none", status: "PENDING" },
  { path: "workers/admission-service/auth.ts", change: "modified", historicalBlob: "b2dbf6509a2e876820df269a2a18fbd65d11f2d1", reviewedSha256: "c6339e4cf974086a0f61fb48d9c5aaa9be2387d1c4ec2913c095ef097638b5aa", reviewId: "BASELINE-V2/LABORATORY", hold: "shared-production-module", status: "PENDING" },
  { path: "workers/admission-service/authority-attestation-config.ts", change: "modified", historicalBlob: "7d2e7cdb75b3cab25343d0116e321d9866158859", reviewedSha256: "8d829524c6074b453325accaba8b2c7e1d9f40836f22650527870f132776c9d1", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/admission-service/authority-attestation-signer.ts", change: "modified", historicalBlob: "44f343d7b47704de88693a99a3f769b9f393fdd7", reviewedSha256: "227339082094a1760f177d2fb46ad1d1452ecd71395ae4aebf22a4d037e4ec67", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/admission-service/authority-attestation.ts", change: "modified", historicalBlob: "7cf8447c691761a5913ea0b276e70208c47600d6", reviewedSha256: "61d80c64409bb15437fc11b2203de613359e9ff7f8d2c14b7529bbd264a22097", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/admission-service/authority.ts", change: "modified", historicalBlob: "e937425eafb460fe08ed54e8fb66d9e17bf4cfdd", reviewedSha256: "978af3510671a4d91cfe197084ab2c95b536ed90fe264c5834389721bffdf2c6", reviewId: "BASELINE-V2/LABORATORY", hold: "shared-production-module", status: "PENDING" },
  { path: "workers/admission-service/index.ts", change: "modified", historicalBlob: "5d5354596d30511cf6e0b7748f211cab96ab0f9a", reviewedSha256: "06be74ef1342e2785d464cc9fd1becc688ec6e8c32680d50a063694d4a03bb39", reviewId: "BASELINE-V2/PRODUCTION_PREPARATION", hold: "none", status: "PENDING" },
  { path: "workers/admission-service/lab-index.ts", change: "added", historicalBlob: null, reviewedSha256: "0ac4a527a73371b5274bfa873929cf5f5efb9c90663c4728ec99a6b83ca3ef27", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/admission-service/operator-command.ts", change: "modified", historicalBlob: "5d2dfbcdb6ae94f61b2a2879b9383e1d49f8c7ee", reviewedSha256: "aa0322cd6e0186e7050c59b73144a9b1d7958f24f3e25d501ed1462a5ac33e64", reviewId: "BASELINE-V2/LABORATORY", hold: "shared-production-module", status: "PENDING" },
  { path: "workers/admission-service/production-index.ts", change: "added", historicalBlob: null, reviewedSha256: "924cd788d3e20394c9b847236f61aac86c18c4c01727c18ded6c2c3923712e4b", reviewId: "BASELINE-V2/PRODUCTION_PREPARATION", hold: "none", status: "PENDING" },
  { path: "workers/admission-service/service.ts", change: "modified", historicalBlob: "22da37a95ed04abb61bea7a32259103c1018f34e", reviewedSha256: "6c61bfa108d3f85f7fa2a4fd776b2e958b76781b85a98cde16998f80ce1c595a", reviewId: "BASELINE-V2/LABORATORY", hold: "shared-production-module", status: "PENDING" },
  { path: "workers/ingress-signer/google-id-token.ts", change: "added", historicalBlob: null, reviewedSha256: "78bf1b131a159654415a32c001e55be8ca7944aa0a4b4d9266f81de9f6c4e07f", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/ingress-signer/index.ts", change: "modified", historicalBlob: "bd531caa3fa65bda79978021fc268b409cbcb1f2", reviewedSha256: "d69da46abc2369a133009216f01603f6819d674859659a0d8ea3e1cc412efadf", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/ingress-signer/laboratory-index.ts", change: "added", historicalBlob: null, reviewedSha256: "9ecbab1409dd69fb9f379cc0a0caad34c6e2f8dfea2a652facb7024d43ee0a2e", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/ingress-signer/signer.ts", change: "modified", historicalBlob: "18f977033fc15b942f007e7f386235239c9aaa7f", reviewedSha256: "3c26770514d19fc42a1e6a27ad43c6bfb993dfe6d245452053e419461c91e24a", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/lab-lifecycle-observer.ts", change: "added", historicalBlob: null, reviewedSha256: "14e57f8d4a52e554f20d1e9c0bed55748a9c31ad8d3e3d6b8bb0eb428fe13227", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/lab-operator-lifecycle-executor.ts", change: "added", historicalBlob: null, reviewedSha256: "f6c98d7f01e6e1a9833f535e3c6cbac933d822a0144356a1a5647dc107b459a5", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/lifecycle-mailbox/dispatch-guard.ts", change: "modified", historicalBlob: "8080226f215ab351cca3560b49ecd7db66ce4302", reviewedSha256: "b24783bebd9754a2515479e6e12d5e6042850d24ee0cdaf1afebede6d5b0f613", reviewId: "BASELINE-V2/GATE_11A_GUARD_EXPORT", hold: "guard-export", status: "PENDING" },
  { path: "workers/lifecycle-mailbox/guard-export.ts", change: "added", historicalBlob: null, reviewedSha256: "ad807439d77908078519f2c9d7c9e90b424b97773b5481a2f96db7592a05f579", reviewId: "BASELINE-V2/GATE_11A_GUARD_EXPORT", hold: "guard-export", status: "PENDING" },
  { path: "workers/lifecycle-mailbox/guard-reader.ts", change: "added", historicalBlob: null, reviewedSha256: "f7cfc64e0f71753ec9f4279625c83d31706c4806fd4dd24cd1e6ddf5a767de4d", reviewId: "BASELINE-V2/GATE_11A_GUARD_EXPORT", hold: "guard-export", status: "PENDING" },
  { path: "workers/lifecycle-mailbox/index.ts", change: "modified", historicalBlob: "3464a3e0bb00ff8192cb2fea1d81f613c3e30020", reviewedSha256: "449a58917de85c1dbbb970d925ac5484af309a72d7c4a7401acaa899a90188f7", reviewId: "BASELINE-V2/GATE_11A_GUARD_EXPORT", hold: "guard-export", status: "PENDING" },
  { path: "workers/lifecycle-mailbox/lab-dispatch-guard.ts", change: "added", historicalBlob: null, reviewedSha256: "8675191e9920366bb0bad1ac80001e82694097d3af0dcaa227c8e92bbce67e0e", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/lifecycle-mailbox/lab-index.ts", change: "added", historicalBlob: null, reviewedSha256: "81d151db986eeedfb5aba366f5aa8bb1732604291e7dd68295d0653acfad8bcc", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/lifecycle-mailbox/lab-processor.ts", change: "added", historicalBlob: null, reviewedSha256: "24515ffc1fc5e3fbd34f042d8f78fc3a1204715c8304a08085e9f31a2aa240ee", reviewId: "BASELINE-V2/LABORATORY", hold: "none", status: "PENDING" },
  { path: "workers/lifecycle-observer.ts", change: "modified", historicalBlob: "04c47007be9f3df61f108b67c4f18d571bff7c2f", reviewedSha256: "c40e4c00243beca44eb552129a1739eb5ad0caff29c681fc9da336791d4cacba", reviewId: "BASELINE-V2/GATE_11A_GUARD_EXPORT", hold: "guard-export", status: "PENDING" },
  { path: "workers/shared/bounded-jwks.ts", change: "modified", historicalBlob: "00c28240f03c35f82fd08fd44e70cfaf9bb5fcc6", reviewedSha256: "9edcf0fb3760ca426fc2ff3b46d95910af11252337032b4262864298683015aa", reviewId: "BASELINE-V2/SHARED_FIX", hold: "none", status: "PENDING" },
]);

const git = (root: string, args: string[]): string => execFileSync("git", args, { cwd: root, encoding: "utf8", maxBuffer: 1 << 28 });
const sha256Lf = (text: string): string => createHash("sha256").update(text.replace(/\r\n/gu, "\n")).digest("hex");
const blobAt = (root: string, commit: string, file: string): string | null => {
  try { return execFileSync("git", ["rev-parse", `${commit}:${file}`], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { return null; }
};

/** Pathspecs that cover `paths` except the reviewed patches AND the APPROVED migrations. PENDING entries are never excluded. */
export function withoutReviewedChanges(paths: readonly string[], registry: readonly ReviewedMigration[] = REVIEWED_MIGRATIONS): string[] {
  return [...withoutReviewedPatches(paths), ...registry.filter((entry) => entry.status === "APPROVED").map((entry) => `:(exclude)${entry.path}`)];
}

export type DriftClassification = {
  /** APPROVED and matching: excluded from the byte-identity diff. */
  authorized: string[];
  /** Registered but still PENDING: recorded evidence only; remains a failure of the byte-identity guard. */
  pending: string[];
  /** Registered, but the working file no longer hashes to the reviewed value (modified after review). */
  modifiedAfterReview: string[];
  /** Not in the registry at all, or the registry's historical half is wrong. */
  unreviewed: string[];
};

/** Classifies every file that differs from `baseline` under `paths` (reviewed patches are already excluded). */
export function classifyDrift(root: string, baseline: string, paths: readonly string[], registry: readonly ReviewedMigration[] = REVIEWED_MIGRATIONS): DriftClassification {
  const differing = git(root, ["diff", "--name-only", baseline, "--", ...withoutReviewedPatches(paths)]).split("\n").filter(Boolean);
  const result: DriftClassification = { authorized: [], pending: [], modifiedAfterReview: [], unreviewed: [] };
  for (const file of differing) {
    const entry = registry.find((candidate) => candidate.path === file);
    if (entry === undefined || blobAt(root, baseline, file) !== entry.historicalBlob) { result.unreviewed.push(file); continue; }
    if (sha256Lf(readFileSync(path.join(root, file), "utf8")) !== entry.reviewedSha256) { result.modifiedAfterReview.push(file); continue; }
    (entry.status === "APPROVED" ? result.authorized : result.pending).push(file);
  }
  return result;
}

/** Both halves for every APPROVED entry (the only ones that exempt anything), for one baseline. */
export function assertMigrationBoundary(root: string, baseline: string, registry: readonly ReviewedMigration[] = REVIEWED_MIGRATIONS): void {
  assert.ok(REVIEWED_PATCHES.length > 0);
  for (const entry of registry.filter((candidate) => candidate.status === "APPROVED")) {
    assert.equal(blobAt(root, baseline, entry.path), entry.historicalBlob, `${entry.path}: the historical file at the baseline is the recorded blob (or absent)`);
    assert.equal(sha256Lf(readFileSync(path.join(root, entry.path), "utf8")), entry.reviewedSha256, `${entry.path}: exactly the reviewed ${entry.reviewId} version`);
  }
}
