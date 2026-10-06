/**
 * Slice 3: the INTERFACE the Defense Plane's front uses for the L2 stage. Types only: no runtime export, so the front (shared with the
 * legacy Slice-1/2 composition) never imports the L2 mechanism. The L2 implementation is `defense/plane/l2-stage.ts`, constructed only by
 * the Slice-3 plane entry.
 */
import type { LaneDecision } from "./lanes";
import type { EnrollSkipReason } from "./enrollment";
import type { LayerRequest } from "./types";

export type EnrollmentEvent =
  | { kind: "L2_ENROLLED"; creditTag: string; fill: [active: number, previous: number] }
  | { kind: "L2_ENROLL_SKIPPED"; skipReason: EnrollSkipReason };

/**
 * One render's enrollment observation: created per forwarded request, single-use, and never selected by anything the client sent.
 * After `finalize()` exactly one disposition (enrolled or skipped, with a reason) has been emitted.
 */
export interface EnrollmentObservation {
  /** The upstream response completed inside the egress deadline. */
  onUpstream(response: { status: number; rawHeaders: readonly string[]; payload: Uint8Array }): void;
  /** The response was completely flushed to the client (the response stream's `finish`). */
  onDelivered(): void;
  finalize(): void;
}

export interface L2Port {
  /** One L2 decision for a request L1 passed. Never rejects: every internal failure is a decision. */
  decide(request: LayerRequest): Promise<LaneDecision>;
  /** An observation for a request on the reviewed form route, or null for every other request. */
  observe(request: LayerRequest, decision: LaneDecision, context: { simulated: boolean; emit(event: EnrollmentEvent): void }): EnrollmentObservation | null;
}
