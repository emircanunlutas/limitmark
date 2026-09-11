import { eq } from "drizzle-orm";
import type { PostgresJsDatabase } from "drizzle-orm/postgres-js";
import type { TestRequest } from "./request-schema";
import { inquiries, inquiryEvents, notificationOutbox } from "./db/schema";
import * as schema from "./db/schema";

export type CreateInquiryResult =
  | { status: "created"; inquiryId: string }
  | { status: "idempotent"; inquiryId: string }
  | { status: "conflict" };

export type CreateInquiryInput = {
  request: TestRequest;
  submissionToken: string;
  payloadFingerprint: string;
};

export interface InquiryRepository {
  create(input: CreateInquiryInput): Promise<CreateInquiryResult>;
}

export class PostgresInquiryRepository implements InquiryRepository {
  constructor(private readonly database: PostgresJsDatabase<typeof schema>) {}

  async create(input: CreateInquiryInput): Promise<CreateInquiryResult> {
    return this.database.transaction(async (transaction) => {
      const inserted = await transaction.insert(inquiries).values({
        ...input.request,
        submissionToken: input.submissionToken,
        payloadFingerprint: input.payloadFingerprint,
      }).onConflictDoNothing({ target: inquiries.submissionToken }).returning({ id: inquiries.id });

      const newInquiry = inserted[0];
      if (newInquiry) {
        await transaction.insert(inquiryEvents).values({
          inquiryId: newInquiry.id,
          eventType: "inquiry_received",
          actorType: "system",
        });
        await transaction.insert(notificationOutbox).values({
          inquiryId: newInquiry.id,
          eventType: "inquiry_received",
          status: "pending",
        });
        return { status: "created", inquiryId: newInquiry.id };
      }

      // The unique index serializes same-token races. At READ COMMITTED, this
      // statement sees the winner after ON CONFLICT has waited for it to commit.
      const existing = await transaction.select({
        id: inquiries.id,
        payloadFingerprint: inquiries.payloadFingerprint,
      }).from(inquiries).where(eq(inquiries.submissionToken, input.submissionToken)).limit(1);
      const prior = existing[0];
      if (!prior) throw new Error("Idempotency winner was not visible");
      if (prior.payloadFingerprint !== input.payloadFingerprint) return { status: "conflict" };
      return { status: "idempotent", inquiryId: prior.id };
    });
  }
}
