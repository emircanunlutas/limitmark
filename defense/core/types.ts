/**
 * Closed vocabularies and shared shapes for the BA0 Defense Plane (application plane only).
 *
 * Nothing in here performs I/O. Every enum is CLOSED: a value outside it is a bug that the ledger turns into an INVALID run, never a
 * new category invented at runtime.
 */

/** Layer namespaces. BA0 populates `a7.*` only; `n3.*` and `t4.*` are reserved and always reported as not_measured. */
export const LAYER_NAMESPACES = { n3: "network-volumetric", t4: "transport", a7: "application" } as const;
export const IMPLEMENTED_NAMESPACES = ["a7"] as const;
export type LayerId = "a7.shape-gate";

/** Every distinct reject reason L1 can give. Exactly one per rejected request; the ledger refuses anything else. */
export const REJECT_REASONS = [
  "a7.method_not_allowed",
  "a7.target_too_long",
  "a7.target_malformed",
  "a7.path_not_allowed",
  "a7.query_not_allowed",
  "a7.header_count_exceeded",
  "a7.header_bytes_exceeded",
  "a7.header_name_invalid",
  "a7.header_value_invalid",
  "a7.host_header_invalid",
  "a7.framing_invalid",
  "a7.content_type_invalid",
  "a7.body_too_large",
  "a7.body_incomplete",
  "a7.body_read_timeout",
  "a7.body_encoding_invalid",
  "a7.form_grammar_invalid",
  "a7.form_field_not_allowed",
  "a7.form_field_duplicate",
  "a7.form_field_count_exceeded",
  "a7.form_field_too_long",
  "a7.form_token_malformed",
] as const;
export type RejectReason = (typeof REJECT_REASONS)[number];

/** `pre_parse`: decided from bounded, constant-cost facts, before any grammar parsing. `grammar`: decided by the form parser. */
export type RejectStage = "pre_parse" | "grammar";

export const REJECT_STATUS: Readonly<Record<RejectReason, number>> = Object.freeze({
  "a7.method_not_allowed": 405,
  "a7.target_too_long": 414,
  "a7.target_malformed": 400,
  "a7.path_not_allowed": 404,
  "a7.query_not_allowed": 400,
  "a7.header_count_exceeded": 431,
  "a7.header_bytes_exceeded": 431,
  "a7.header_name_invalid": 400,
  "a7.header_value_invalid": 400,
  "a7.host_header_invalid": 400,
  "a7.framing_invalid": 400,
  "a7.content_type_invalid": 415,
  "a7.body_too_large": 413,
  "a7.body_incomplete": 400,
  "a7.body_read_timeout": 408,
  "a7.body_encoding_invalid": 400,
  "a7.form_grammar_invalid": 400,
  "a7.form_field_not_allowed": 422,
  "a7.form_field_duplicate": 422,
  "a7.form_field_count_exceeded": 422,
  "a7.form_field_too_long": 422,
  "a7.form_token_malformed": 422,
});

export const REJECT_STAGE: Readonly<Record<RejectReason, RejectStage>> = Object.freeze({
  "a7.method_not_allowed": "pre_parse",
  "a7.target_too_long": "pre_parse",
  "a7.target_malformed": "pre_parse",
  "a7.path_not_allowed": "pre_parse",
  "a7.query_not_allowed": "pre_parse",
  "a7.header_count_exceeded": "pre_parse",
  "a7.header_bytes_exceeded": "pre_parse",
  "a7.header_name_invalid": "pre_parse",
  "a7.header_value_invalid": "pre_parse",
  "a7.host_header_invalid": "pre_parse",
  "a7.framing_invalid": "pre_parse",
  "a7.content_type_invalid": "pre_parse",
  "a7.body_too_large": "pre_parse",
  "a7.body_incomplete": "pre_parse",
  "a7.body_read_timeout": "pre_parse",
  "a7.body_encoding_invalid": "grammar",
  "a7.form_grammar_invalid": "grammar",
  "a7.form_field_not_allowed": "grammar",
  "a7.form_field_duplicate": "grammar",
  "a7.form_field_count_exceeded": "grammar",
  "a7.form_field_too_long": "grammar",
  "a7.form_token_malformed": "grammar",
});

/** What a layer returns. A layer never throws past the composer and never returns anything outside this union. */
export type LayerVerdict = { kind: "pass" } | { kind: "reject"; reason: RejectReason };

export const LAYER_ERROR_KINDS = ["throw", "timeout", "invalid_verdict"] as const;
export type LayerErrorKind = (typeof LAYER_ERROR_KINDS)[number];

/** The composer's explicit result for one layer evaluation: exactly one of pass | reject | shed | error. */
export type LayerOutcome =
  | { kind: "pass" }
  | { kind: "reject"; reason: RejectReason }
  | { kind: "shed" }
  | { kind: "error"; errorKind: LayerErrorKind };

/**
 * Slice 1 has ONE failure policy: an unexpected layer error is an explicit L1_ERROR and the request is refused (fail closed).
 * An error is never an ordinary pass. A distinct degraded/quarantine outcome is RESERVED for a later slice; it is not produced
 * anywhere, and when it exists it must not be equivalent to pass.
 */
export type FailurePolicy = "fail_closed";
export const FAILURE_POLICIES: readonly FailurePolicy[] = ["fail_closed"];
export const RESERVED_OUTCOMES = ["degraded"] as const;

export type BodyStatus = "none" | "complete" | "declared_oversize" | "overflow" | "timeout" | "aborted";

/**
 * What a layer is allowed to see. Deliberately has no traffic-class label, no harness correlation id and no connection identity:
 * a layer can only judge the SHAPE of the request.
 */
export type LayerRequest = {
  readonly method: string;
  /** The request target exactly as received (origin-form expected). */
  readonly target: string;
  readonly headers: readonly (readonly [name: string, value: string])[];
  readonly bodyStatus: BodyStatus;
  /** Present only when bodyStatus is "complete"; bounded by the front before any layer runs. */
  readonly body: Uint8Array | null;
};

export interface Layer {
  readonly id: LayerId;
  evaluate(request: LayerRequest): LayerVerdict | Promise<LayerVerdict>;
}

/** Limits L1 enforces. Constants rather than options: a request cannot influence them. */
export const L1_LIMITS = Object.freeze({
  maxTargetBytes: 2048,
  maxQueryBytes: 64,
  maxHeaderCount: 48,
  maxHeaderBytes: 8192,
  maxHeaderNameBytes: 64,
  /** Equals INGRESS_MAX_BODY_BYTES in the application; pinned by a contract test, not imported. */
  maxBodyBytes: 32_768,
  maxFormFields: 16,
  maxFieldNameBytes: 32,
  maxFieldEncodedBytes: 12_000,
  submissionTokenLength: 43,
});

/**
 * Header names that only a trusted hop may set. The front removes them from what layers see and from what is forwarded:
 * a client cannot inject them. (The harness correlation header is read by the front for measurement and removed like the rest.)
 */
export const NONCE_HEADER = "x-ba0-nonce";
export const HOP_HEADER = "x-ba0-hop";
export const OUTCOME_HEADER = "x-ba0-outcome";
export const SPOOFABLE_HEADER_PATTERNS: readonly RegExp[] = [
  /^x-ba0-/,
  /^x-forwarded-/,
  /^forwarded$/,
  /^x-real-ip$/,
  /^x-client-ip$/,
  /^true-client-ip$/,
  /^cf-connecting-ip$/,
  /^cf-ipcountry$/,
  /^x-limitmark-/,
  /^x-vercel-/,
  /^x-original-url$/,
  /^x-rewrite-url$/,
  /^x-http-method-override$/,
];

export function isSpoofableHeader(lowerCaseName: string): boolean {
  return SPOOFABLE_HEADER_PATTERNS.some((pattern) => pattern.test(lowerCaseName));
}

/** Opaque per-request correlation nonce: 16 random bytes, base64url (22 chars). */
export const NONCE_PATTERN = /^[A-Za-z0-9_-]{22}$/;

export type Lane = "control" | "protected";
