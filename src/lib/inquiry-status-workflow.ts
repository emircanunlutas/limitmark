import { inquiryStatusValues } from "./db/schema";

export type InquiryStatus = (typeof inquiryStatusValues)[number];
export type ActiveInquiryStatus = Exclude<InquiryStatus, "archived">;

const transitionGraph = {
  received: ["in_review", "declined"],
  in_review: ["awaiting_scope", "declined"],
  awaiting_scope: ["proposal_sent", "declined"],
  proposal_sent: ["approved", "declined"],
  approved: ["completed"],
  completed: [],
  declined: [],
  archived: [],
} as const satisfies Record<InquiryStatus, readonly InquiryStatus[]>;

export const inquiryStatusTransitionGraph: Readonly<Record<InquiryStatus, readonly InquiryStatus[]>> = transitionGraph;

export function isInquiryStatus(value: unknown): value is InquiryStatus {
  return typeof value === "string" && inquiryStatusValues.some((status) => status === value);
}

export function isActiveInquiryStatus(value: unknown): value is ActiveInquiryStatus {
  return isInquiryStatus(value) && value !== "archived";
}

export function allowedInquiryStatusTransitions(status: InquiryStatus): readonly InquiryStatus[] {
  return inquiryStatusTransitionGraph[status];
}

export function canTransitionInquiryStatus(current: InquiryStatus, next: InquiryStatus): boolean {
  return allowedInquiryStatusTransitions(current).some((candidate) => candidate === next);
}
