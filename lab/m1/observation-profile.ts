/**
 * Observation profiles. The evidence of the independent observers is judged under ONE explicit profile, and the profile is chosen by the VERIFIER (from the verified pre-run
 * environment commitment), never by the result file:
 *
 *   LOCAL_LOOPBACK  the local harness: separate local processes on loopback, at least five distinct process ids (unchanged requirement).
 *   REMOTE_PRIVATE  observers on separate machines in the private lane: distinct observer ROLES with deployment identities and private addresses that must equal the ones
 *                   committed before the run. Process ids are irrelevant here and are not accepted as proof.
 *
 * What a profile check can and cannot show. Deployment identities and addresses are SELF-REPORTED by the canary, by the collector and in the metadata; agreement of three
 * self-reports with the commitment is consistency, not proof of independent custody or of who produced the bytes. That needs separate principals, credentials and storage
 * (see M1-EXECUTION-READINESS.md section 3), and authenticated producers, which do not exist yet. A file that CLAIMS authenticated or independent custody is rejected, because this
 * check cannot establish it. Byte consistency (the seal) is a separate matter again.
 */
export type ObservationProfile = "LOCAL_LOOPBACK" | "REMOTE_PRIVATE";
export type ObserverIdentity = { deploymentId: string; address: string };
/** What the verifier expects, derived from a verified commitment (or the default local expectation when none is supplied). */
export type ExpectedObservation = { profile: ObservationProfile; canary: ObserverIdentity | null; collector: ObserverIdentity | null; targetAddress: string | null; commitmentDigest: string | null };

export const LOCAL_EXPECTATION: ExpectedObservation = { profile: "LOCAL_LOOPBACK", canary: null, collector: null, targetAddress: null, commitmentDigest: null };
export const REMOTE_LIMITATIONS = ["observer_identities_self_reported_not_authenticated", "independent_custody_not_established_by_this_check", "producer_authenticity_not_established", "remote_profile_simulated_evidence_does_not_prove_real_off_host_deployment_unless_the_commitment_and_custody_are_real"];

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/u;
export const isPrivateIpv4 = (address: string): boolean => {
  if (!IPV4.test(address)) return false;
  const [a, b] = address.split(".").map(Number) as [number, number];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
};
export const DEPLOYMENT_ID = /^[A-Za-z0-9._:/-]{1,128}$/u;
export function readIdentity(value: unknown): ObserverIdentity | null {
  if (!isRecord(value) || typeof value.deploymentId !== "string" || typeof value.address !== "string") return null;
  if (!DEPLOYMENT_ID.test(value.deploymentId) || !isPrivateIpv4(value.address)) return null;
  return { deploymentId: value.deploymentId, address: value.address };
}
const sameIdentity = (a: ObserverIdentity, b: ObserverIdentity): boolean => a.deploymentId === b.deploymentId && a.address === b.address;
const CUSTODY_CLAIM_KEYS = ["authenticated", "authenticatedCustody", "independentCustody", "custodyAuthenticated", "producerAuthenticated"];

export type RemoteCheck = { missing: string[]; reasons: string[] };
/** Pure; never throws. `missing` = required identity evidence absent (the caller returns ERROR); `reasons` = contradictions (REJECT). */
export function evaluateRemoteProfile(input: { meta: Record<string, unknown>; canary: Record<string, unknown>; declaration: unknown; expected: ExpectedObservation }): RemoteCheck {
  const missing: string[] = []; const reasons: string[] = [];
  const { expected } = input;
  if (expected.canary === null || expected.collector === null) missing.push("m1.obs.remote.expected_identities_missing_from_commitment");
  const declaration = isRecord(input.declaration) ? input.declaration : null;
  const metaObservers = isRecord(input.meta.observers) ? input.meta.observers : {};
  const canaryReports = [readIdentity(input.canary.observer), readIdentity(metaObservers.canary)];
  const collectorReport = declaration === null ? null : readIdentity(declaration.observer);
  if (canaryReports.some((r) => r === null)) missing.push("m1.obs.remote.canary_identity_missing");
  if (collectorReport === null) missing.push("m1.obs.remote.collector_identity_missing");
  if (input.meta.loopbackOnly !== false || input.meta.topology !== "private-lane") reasons.push("m1.obs.remote.metadata_contradicts_remote_profile");
  for (const doc of [input.meta, input.canary, declaration ?? {}]) if (CUSTODY_CLAIM_KEYS.some((k) => (doc as Record<string, unknown>)[k] === true)) reasons.push("m1.obs.remote.custody_claim_cannot_be_verified_here");
  if (missing.length === 0) {
    const [canaryOwn, canaryMeta] = canaryReports as ObserverIdentity[]; const collector = collectorReport!;
    if (!sameIdentity(canaryOwn, canaryMeta)) reasons.push("m1.obs.remote.canary_identity_inconsistent_between_results_and_metadata");
    if (expected.canary !== null && !sameIdentity(canaryOwn, expected.canary)) reasons.push("m1.obs.remote.canary_identity_differs_from_commitment");
    if (expected.collector !== null && !sameIdentity(collector, expected.collector)) reasons.push("m1.obs.remote.collector_identity_differs_from_commitment");
    if (canaryOwn.deploymentId === collector.deploymentId || canaryOwn.address === collector.address) reasons.push("m1.obs.remote.canary_and_collector_not_distinct");
    if (expected.targetAddress !== null && (canaryOwn.address === expected.targetAddress || collector.address === expected.targetAddress)) reasons.push("m1.obs.remote.observer_address_equals_target");
  }
  return { missing: [...new Set(missing)], reasons: [...new Set(reasons)] };
}
