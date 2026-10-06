/**
 * Field qualification: the level's STATE MACHINE, the first-STOP LATCH and the bounded, ordered FINALIZATION sequence. No I/O of its own:
 * every effect is a function the runner passes in, so the whole machine runs on a fake clock in tests.
 *
 *   PREFLIGHT -> TOPOLOGY_UP -> BASELINE -> ARMED -> WINDOW -> RESIDUAL -> QUIET -> RECOVERY -> FINALIZING -> DONE
 *   (any state from TOPOLOGY_UP to RECOVERY)  --STOP-->  STOPPING -> DRAINING -> SNAPSHOT -> FINALIZING -> DONE
 *
 * A STOP must PRESERVE the evidence that explains it, so the sequence is ordered and every step has a hard timeout:
 *
 *   1 latch the first reason, class and time (first writer wins; later reasons are recorded, never replace it)
 *   2 close the public ingress                    3 allow no new phase or work           4 mark the state STOPPING
 *   5 drain accepted work and the IPC channels    6 collect final telemetry from every process
 *   7 take the final /proc, host and exposure snapshot
 *   8 freeze the collector, finalize, close the journal and serialize the evidence (core manifest first)
 *   9 terminate the children gracefully; a kill is only the bounded last fallback, after the evidence attempts
 *
 * A step that times out or fails is RECORDED and never stops the sequence; the whole sequence has a hard cap after which only the essential
 * steps (the core manifest and the termination) still run.
 */
import { classOf, type Reason, type ReasonClass, type ReasonCode } from "./field-verdict";

export type FieldState =
  | "CREATED" | "PREFLIGHT" | "TOPOLOGY_UP" | "BASELINE" | "ARMED" | "WINDOW" | "RESIDUAL" | "QUIET" | "RECOVERY"
  | "STOPPING" | "DRAINING" | "SNAPSHOT" | "FINALIZING" | "DONE";

const NORMAL: readonly FieldState[] = ["CREATED", "PREFLIGHT", "TOPOLOGY_UP", "BASELINE", "ARMED", "WINDOW", "RESIDUAL", "QUIET", "RECOVERY", "FINALIZING", "DONE"];
/** States from which a STOP may begin. */
const STOPPABLE: ReadonlySet<FieldState> = new Set(["TOPOLOGY_UP", "BASELINE", "ARMED", "WINDOW", "RESIDUAL", "QUIET", "RECOVERY"]);

export class IllegalTransition extends Error {
  constructor(from: FieldState, to: FieldState) {
    super(`illegal transition ${from} -> ${to}`);
    this.name = "IllegalTransition";
  }
}

export type LatchedReason = { code: ReasonCode; cls: ReasonClass; atMs: number; wallMs: number; detail?: string };

export class FieldMachine {
  private current: FieldState = "CREATED";
  private readonly history: { state: FieldState; atMs: number }[] = [];
  private readonly reasons: LatchedReason[] = [];
  private first: LatchedReason | null = null;
  private stopBegan = false;
  private refusedAtPreflight = false;

  constructor(private readonly clock: () => number, private readonly wall: () => number = () => Date.now()) {
    this.history.push({ state: "CREATED", atMs: clock() });
  }

  get state(): FieldState { return this.current; }
  get stopped(): boolean { return this.stopBegan; }
  get refused(): boolean { return this.refusedAtPreflight; }
  get firstReason(): LatchedReason | null { return this.first; }
  allReasons(): readonly LatchedReason[] { return this.reasons; }
  transitions(): readonly { state: FieldState; atMs: number }[] { return this.history; }

  /** No new phase, canary or work may start once a STOP began or the level reached finalization. */
  canStartWork(): boolean { return !this.stopBegan && this.current !== "FINALIZING" && this.current !== "DONE"; }

  private set(next: FieldState): void {
    this.current = next;
    this.history.push({ state: next, atMs: this.clock() });
  }

  /** The normal forward step. Anything but the next state in the normal order (or any step once a STOP began) is refused. */
  advance(next: FieldState): void {
    if (this.stopBegan) {
      // After a STOP the only legal path is STOPPING -> DRAINING -> SNAPSHOT -> FINALIZING -> DONE.
      const order: FieldState[] = ["STOPPING", "DRAINING", "SNAPSHOT", "FINALIZING", "DONE"];
      const at = order.indexOf(this.current);
      if (at < 0 || order[at + 1] !== next) throw new IllegalTransition(this.current, next);
      this.set(next);
      return;
    }
    const at = NORMAL.indexOf(this.current);
    if (at < 0 || NORMAL[at + 1] !== next) throw new IllegalTransition(this.current, next);
    this.set(next);
  }

  /**
   * Records a reason. The FIRST one is latched atomically (first writer wins) and, when it belongs to a stoppable state and `stops` is true,
   * begins the STOP: the state becomes STOPPING. Later reasons are appended and never replace it. Returns whether this call was the first.
   */
  latch(reason: Reason, stops = true): boolean {
    const entry: LatchedReason = { code: reason.code, cls: classOf(reason.code), atMs: this.clock(), wallMs: this.wall(), ...(reason.detail !== undefined ? { detail: reason.detail } : {}) };
    if (this.reasons.length < 64) this.reasons.push(entry);
    const wasFirst = this.first === null;
    if (wasFirst) this.first = entry;
    if (stops && !this.stopBegan && STOPPABLE.has(this.current)) { this.stopBegan = true; this.set("STOPPING"); }
    return wasFirst;
  }

  /** A preflight refusal: nothing was bound, nothing ran. The level goes straight to DONE. */
  refuse(reason: Reason): void {
    this.latch(reason, false);
    this.refusedAtPreflight = true;
    this.current = "DONE";
    this.history.push({ state: "DONE", atMs: this.clock() });
  }
}

// ---------------------------------------------------------------------------
// The bounded, ordered sequence
// ---------------------------------------------------------------------------

export type SequenceStep = {
  name: string;
  /** Hard timeout of this step. */
  budgetMs: number;
  /** An essential step still runs after the hard cap (the core manifest and the termination). */
  essential: boolean;
  run: () => Promise<void>;
  /** Called synchronously just before the step starts (the runner advances the state machine here). Its errors are ignored. */
  before?: () => void;
};

export type StepResult = { name: string; ok: boolean; timedOut: boolean; skippedByCap: boolean; ms: number; error: string | null };

/** Runs one step with a hard timeout. Never throws; the step's own late completion is ignored. */
async function runBounded(step: SequenceStep, budgetMs: number, clock: () => number): Promise<StepResult> {
  const started = clock();
  try { step.before?.(); } catch { /* a state-machine hook never stops the sequence */ }
  let timer: NodeJS.Timeout | undefined;
  const outcome = await Promise.race([
    step.run().then(() => "ok" as const, (error: unknown) => ({ error: error instanceof Error ? error.name : "NonError" })),
    new Promise<"timeout">((resolve) => { timer = setTimeout(() => resolve("timeout"), Math.max(1, budgetMs)); }),
  ]);
  if (timer) clearTimeout(timer);
  const ms = Math.round(clock() - started);
  if (outcome === "ok") return { name: step.name, ok: true, timedOut: false, skippedByCap: false, ms, error: null };
  if (outcome === "timeout") return { name: step.name, ok: false, timedOut: true, skippedByCap: false, ms, error: null };
  return { name: step.name, ok: false, timedOut: false, skippedByCap: false, ms, error: outcome.error };
}

/**
 * Runs the steps in order. Each is bounded by its own budget; the sequence as a whole by `hardCapMs`: once the cap is spent, every
 * non-essential step is skipped (and recorded as skipped), while an essential one still runs with whatever budget it has left (at least
 * its own minimum), so the evidence core is written and the processes are terminated no matter what an earlier step did.
 *
 * `results` may be supplied: each step's result is pushed as it COMPLETES, so the evidence step (which runs inside the sequence) can record the steps
 * that finished before it. (The evidence cannot record its own writing or the termination that follows it.)
 */
export async function runSequence(steps: readonly SequenceStep[], hardCapMs: number, clock: () => number = () => performance.now(), results: StepResult[] = []): Promise<StepResult[]> {
  const begun = clock();
  for (const step of steps) {
    const spent = clock() - begun;
    const remaining = hardCapMs - spent;
    if (remaining <= 0 && !step.essential) { results.push({ name: step.name, ok: false, timedOut: false, skippedByCap: true, ms: 0, error: null }); continue; }
    results.push(await runBounded(step, Math.min(step.budgetMs, step.essential ? step.budgetMs : Math.max(1, remaining)), clock));
  }
  return results;
}
