/**
 * Milestone 2: interface-only contract for the pure origin-local capacity controller.
 *
 * Types ONLY — zero runtime exports, zero imports (mirrors `defense/core/l2-port.ts` and `defense/core/override-port.ts`).
 * Nothing here imports L2, telemetry, the Defense Plane, the Origin Boundary runtime, or any external package.
 */

export type AccessCategory = "public" | "operational";
export type HttpScheme = "http" | "https";
export type OperationMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE";
export type OperationEffect = "read" | "write";

export type ChannelSpec = {
  readonly id: string;
  readonly access: AccessCategory;
  readonly principal: string;
  readonly audience: string;
  readonly scheme: HttpScheme;
  readonly authority: string;
};

export type CapacityLimits = {
  readonly activeUnits: number;
  readonly maxQueued: number;
  readonly maxQueuedBytes: number;
  readonly maxBodyBytes: number;
  readonly metadataBytesPerRequest: number;
  readonly proofWindowMs: number;
  readonly dispatchMarginMs: number;
  readonly executionTimeoutMs: number;
  readonly callerBudgetMs: number;
};

export type ClassSpec = {
  readonly id: string;
  readonly access: AccessCategory;
  readonly reservedUnits: number;
  readonly maxActiveUnits: number;
  readonly maxQueued: number;
  readonly maxWaitMs: number;
};

export type OperationBodySpec = {
  readonly mediaType: string;
  readonly maxBytes: number;
  readonly requireSameOrigin: boolean;
};

export type OperationSpec = {
  readonly id: string;
  readonly channel: string;
  readonly method: OperationMethod;
  readonly path: string;
  readonly queries: readonly string[];
  readonly body: OperationBodySpec | null;
  readonly classId: string;
  readonly costUnits: number;
  readonly effect: OperationEffect;
};

export type JourneyStepSpec = {
  readonly operationId: string;
  readonly target: string;
  readonly status: number;
  readonly result: string;
  readonly receipt: string | null;
};

export type JourneySpec = {
  readonly id: string;
  readonly minCompletionBps: number;
  readonly p95LimitMs: number;
  readonly recoveryLimitMs: number;
  readonly steps: readonly JourneyStepSpec[];
};

export type DomainSpec = {
  readonly id: string;
  readonly backendRef: string;
  readonly instances: 1;
};

export type CustomerOriginPolicyManifest = {
  readonly version: "customer-origin-policy-v1";
  readonly revision: number;
  readonly tenantId: string;
  readonly deploymentId: string;
  readonly requestProfile: "bounded-http-v1";
  readonly unsupported: "deny";
  readonly domain: DomainSpec;
  readonly channels: readonly ChannelSpec[];
  readonly capacity: CapacityLimits;
  readonly classes: readonly ClassSpec[];
  readonly operations: readonly OperationSpec[];
  readonly journeys: readonly JourneySpec[];
};

/** Trusted out-of-band activation record that pins a policy's scope, revision and exact UTF-8 byte digest. */
export type PolicyActivationRecord = {
  readonly tenantId: string;
  readonly deploymentId: string;
  readonly domainId: string;
  readonly revision: number;
  readonly expectedDigest: string;
};

/**
 * A validated, deeply frozen customer-origin policy compiled strictly from immutable UTF-8 source bytes
 * and matched against a trusted `PolicyActivationRecord`. Authoritative internals live in a private WeakMap.
 */
export type CompiledCustomerOriginPolicy = {
  readonly manifest: CustomerOriginPolicyManifest;
  readonly digest: string;
  readonly sharedUnits: number;
};

export type VerifiedScope = {
  readonly tenantId: string;
  readonly deploymentId: string;
  readonly domainId: string;
  readonly digest: string;
};

export type VerifiedRequestFacts = VerifiedScope & {
  readonly principal: string;
  readonly audience: string;
  readonly scheme: string;
  readonly authority: string;
  readonly method: string;
  readonly target: string;
  readonly mediaType: string | null;
  readonly bodyBytes: number;
  readonly origin: string | null;
};

/** Authenticated verification output with proof expiration cryptographically bound inside the verifier result. */
export type AuthenticatedRequestData = VerifiedRequestFacts & {
  readonly proofExpiresAtWallMs: number;
};

export type VerifierResult =
  | { readonly ok: true; readonly authenticated: AuthenticatedRequestData }
  | { readonly ok: false; readonly reason: "unverified" };

/**
 * Trusted request-verification capability injected into a classifier or controller at construction time.
 * When provided, authenticate the complete semantics against the supplied body view. Candidate and
 * verification workspace are call-scoped. The view is revoked when verification finishes.
 * No global sealer exists in `defense/core/`; synthetic verifiers remain confined to tests.
 */
export interface OriginRequestVerifier<TInput = unknown> {
  verify(candidate: TInput, policy: CompiledCustomerOriginPolicy, wallNowMs: number, body?: VerificationBody): VerifierResult;
}

/** Stage 2 passes the owned copy used for admission through this revocable, read-only view. */
export interface VerificationBody {
  readonly byteLength: number;
  byteAt(index: number): number | undefined;
}

export type ClassificationFailureKind = "unverified" | "scope-mismatch" | "untrusted-channel" | "unsupported";

export type ClassificationResult =
  | { readonly kind: ClassificationFailureKind }
  | {
      readonly kind: "classified";
      readonly operationId: string;
      readonly classId: string;
      readonly channelId: string;
      readonly access: AccessCategory;
      readonly costUnits: number;
      readonly effect: OperationEffect;
      readonly bodyBytes: number;
      readonly proofExpiresAtWallMs: number;
    };

declare const capacityIdentity: unique symbol;
type Identity<Name extends string> = { readonly [capacityIdentity]: Name };

export type CapacityAttempt = Identity<"attempt">;
export type CapacityLease = Identity<"lease">;
export type CapacityExecution = Identity<"execution">;
export type CapacityGeneration = Identity<"generation">;
export type CapacitySettlementEvent = Identity<"settlement">;
export type CapacityPool = "reserved" | "shared";
export type LeaseState = "active" | "ambiguous-held" | "settled";
export type AttemptRejection = ClassificationFailureKind | "clock-invalid" | "deadline-invalid" | "preparation-bytes-exceeded" | "queue-disabled" |
  "class-queue-full" | "domain-queue-full" | "queue-bytes-exceeded";
export type WaitExpiryReason = "proof-expired" | "caller-deadline-exceeded" | "wait-timeout";

export type AttemptStatus =
  | { readonly kind: "preparing" | "ready" }
  | { readonly kind: "queued"; readonly bytes: number }
  | { readonly kind: "granted"; readonly pool: CapacityPool; readonly lease: CapacityLease }
  | { readonly kind: "cancelled"; readonly reason: "cancelled" | "controller-closed" }
  | { readonly kind: "rejected"; readonly reason: AttemptRejection }
  | { readonly kind: "expired"; readonly reason: WaitExpiryReason };

export type CapacityUsage = {
  readonly reserved: number;
  readonly shared: number;
  readonly ambiguous: number;
  readonly queued: number;
  readonly bytes: number;
};

export type CapacitySnapshot = CapacityUsage & {
  readonly closed: boolean;
  readonly preparationSlots: number;
  readonly leases: number;
  readonly classes: readonly (CapacityUsage & { readonly id: string })[];
};

/** Request-side capability. Preparation, time, and execution authority are held separately. */
export interface OriginCapacityPort {
  cancel(attempt: CapacityAttempt): boolean;
  attemptStatus(attempt: CapacityAttempt): AttemptStatus | undefined;
  leaseState(lease: CapacityLease): LeaseState | undefined;
  snapshot(): CapacitySnapshot;
  hasPendingMaintenance(): boolean;
}

/** Synchronous isolated clock. Bounds remain valid through the callback-free decision segment. */
export interface CapacityDecisionClock {
  monotonicMs(): number;
  /** Upper wall bound valid from this call through completion of the decision segment. */
  wallUpperMs(): number;
}

export type CapacityRequestInput<T> = {
  readonly candidate: T;
  readonly body?: Uint8Array;
  readonly callerDeadlineMonoMs?: number;
};

export type CapacityExecutionIdentity = {
  readonly generation: CapacityGeneration;
  readonly lease: CapacityLease;
  readonly execution: CapacityExecution;
};

export type CapacityExecutionEvidence = CapacityExecutionIdentity & (
  | { readonly kind: "completed" | "aborted" | "timeout-confirmed" | "never-started" }
  | { readonly kind: "ambiguous"; readonly hardStopMonoMs?: number }
);

/**
 * Verify the report against the named execution. A hard stop attests that this execution cannot
 * run at or after that instant, including delayed start. A never-started report requires a start fence.
 */
export interface CapacityExecutionVerifier<T> {
  verify(identity: CapacityExecutionIdentity, evidence: T): CapacityExecutionEvidence | null;
}

