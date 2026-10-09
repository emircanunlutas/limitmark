import type { PlaneEvent } from "../../defense/core/ledger";
import { n2ExerciseSpec } from "../../lab/defense/n2-measurement";
import { BA0_FIELD_C2_SALVO_V1 } from "../../lab/defense/field-thresholds";
import { GENERATOR_PROVENANCE, SALVO_DIAGNOSTICS_SCHEMA, SalvoRequestRecorder, type GeneratorSalvoDiagnostics, type ServerSalvoDiagnostics } from "../../lab/defense/salvo-diagnostics";
import { SalvoServerObserver } from "../../lab/defense/salvo-measurement";
import { SALVO_SPEC } from "../../lab/defense/salvo-spec";

/** Shared plane-event and generator-row fixtures for the salvo diagnostics suites. Synthetic: nothing here is real R2 evidence. */

// ------------------------------------------------------------------------------------------------------------------ plane event fixtures
export type Spec = {
  nonce: string; cls: "open" | "mutation"; at: number; end: number; status?: number; shed?: boolean; fin?: "responded" | "aborted" | "pending";
  l1?: "passed" | "rejected"; noL2?: boolean; external?: boolean;
};
type Raw = Omit<PlaneEvent, "seq">;

/** Plane events of one request, in the plane's own lifecycle order, with times strictly inside [at, end]. */
function requestEvents(r: Spec): { t: number; e: Raw }[] {
  const d = r.end - r.at; const at = (f: number) => r.at + d * f;
  const out: { t: number; e: Raw }[] = [];
  const push = (t: number, e: Omit<Raw, "nonce" | "t">) => out.push({ t, e: { nonce: r.nonce, t, ...e } as Raw });
  push(r.at, r.external === false ? { kind: "INGRESS_ACCEPTED" } : { kind: "INGRESS_ACCEPTED", ingress: "external" });
  push(at(0.05), { kind: "L1_ENTERED" });
  if (r.l1 === "rejected") push(at(0.1), { kind: "L1_REJECTED", reason: "shape" as never });
  else {
    push(at(0.1), { kind: "L1_PASSED" });
    if (!r.noL2) {
      push(at(0.15), { kind: "L2_ENTERED" });
      push(at(0.2), r.shed
        ? { kind: "L2_DECIDED", class: r.cls, lane: "unverified", outcome: "shed", shedReason: "lane_budget" }
        : { kind: "L2_DECIDED", class: r.cls, lane: r.cls === "mutation" ? "unverified" : "open", outcome: "admitted" });
      if (!r.shed) { push(at(0.3), { kind: "EGRESS_ATTEMPTED" }); push(at(0.8), { kind: "EGRESS_RESPONDED" }); }
    }
  }
  const fin = r.fin ?? "responded";
  if (fin === "responded") push(r.end, { kind: "INGRESS_RESPONDED", status: r.status ?? (r.shed ? 503 : 200) });
  else if (fin === "aborted") push(r.end, { kind: "INGRESS_ABORTED" });
  return out;
}

/** The plane stream: events ordered by time (ties by creation order) and numbered gaplessly, as the collector receives them. */
export function stream(specs: readonly Spec[]): PlaneEvent[] {
  const all = specs.flatMap(requestEvents).map((x, i) => ({ ...x, i }));
  all.sort((a, b) => a.t - b.t || a.i - b.i);
  return all.map((x, index) => ({ ...x.e, seq: index + 1 }) as PlaneEvent);
}

export type CampaignOptions = { shedOdd?: boolean; reversed?: (pair: number) => boolean; zeroOverlap?: (pair: number) => boolean };
/** 750 pairs at 80 ms: even = two reads, odd = read + mutation. Nonces are long and secret-looking on purpose (they must never reach evidence). */
export function campaign(options: CampaignOptions = {}): Spec[] {
  const specs: Spec[] = [];
  for (let p = 0; p < SALVO_SPEC.pairs; p++) {
    const base = p * 80; const odd = p % 2 === 1; const shed = odd && options.shedOdd === true;
    const nonce = (slot: number) => `nonce-secret-token-${p}-${slot}-aaaaaaaaaaaaaaaaaaaa`;
    const a: Spec = { nonce: nonce(0), cls: "open", at: base, end: base + 6 };
    const b: Spec = odd ? { nonce: nonce(1), cls: "mutation", at: base + 0.25, end: base + 0.25 + (shed ? 0.75 : 6), shed } : { nonce: nonce(1), cls: "open", at: base + 0.25, end: base + 6.25 };
    if (options.reversed?.(p)) { b.at = base; b.end = base + (shed ? 0.75 : 6); a.at = base + 0.25; a.end = base + 6.25; }
    if (options.zeroOverlap?.(p)) { b.at = base; b.end = base + 0.7; a.at = base + 0.9; a.end = base + 6.9; }
    specs.push(a, b);
  }
  return specs;
}

export const record = (events: readonly PlaneEvent[]): ServerSalvoDiagnostics => {
  const recorder = new SalvoRequestRecorder(); for (const event of events) recorder.observe(event); return recorder.snapshot();
};
export const observe = (events: readonly PlaneEvent[]) => {
  const observer = new SalvoServerObserver(n2ExerciseSpec(BA0_FIELD_C2_SALVO_V1)); for (const event of events) observer.observe(event); return observer;
};

/** Generator diagnostics matching a campaign: dispatch slot 0 is the read, slot 1 the second request (a mutation on odd pairs). */
export function generatorDiagnostics(statusOf: (pair: number, slot: 0 | 1) => number | null = (p, s) => (p % 2 === 1 && s === 1 ? 503 : 200), offset = 0): GeneratorSalvoDiagnostics {
  const requests: GeneratorSalvoDiagnostics["requests"] = [];
  for (let p = 0; p < SALVO_SPEC.pairs; p++) for (const slot of [0, 1] as const) {
    const startMs = p * 80 + slot * 0.25 + offset;
    requests.push({ pair: p, slot, startMs, handoffMs: startMs + 0.05, settledMs: startMs + 6, status: statusOf(p, slot) });
  }
  return { schema: SALVO_DIAGNOSTICS_SCHEMA, side: "generator", provenance: GENERATOR_PROVENANCE, capacity: { maxRequests: 1500 }, requests };
}


/** Authoritative-style generator pair records derived from the diagnostic rows (what `salvo.pairs` holds for the same campaign). */
export function generatorPairsFrom(g: GeneratorSalvoDiagnostics): { index: number; startsMs: (number | null)[]; settledMs: (number | null)[] }[] {
  const pairs = Array.from({ length: SALVO_SPEC.pairs }, (_, index) => ({ index, startsMs: [null, null] as (number | null)[], settledMs: [null, null] as (number | null)[] }));
  for (const r of g.requests) { pairs[r.pair].startsMs[r.slot] = r.startMs; pairs[r.pair].settledMs[r.slot] = r.settledMs; }
  return pairs;
}
