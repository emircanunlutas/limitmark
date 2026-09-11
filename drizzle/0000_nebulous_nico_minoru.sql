CREATE TYPE "public"."inquiry_actor_type" AS ENUM('system', 'admin');--> statement-breakpoint
CREATE TYPE "public"."inquiry_event_type" AS ENUM('inquiry_received', 'status_changed', 'note_added', 'archived', 'restored', 'notification_sent', 'notification_failed');--> statement-breakpoint
CREATE TYPE "public"."inquiry_status" AS ENUM('received', 'in_review', 'awaiting_scope', 'proposal_sent', 'approved', 'declined', 'completed', 'archived');--> statement-breakpoint
CREATE TYPE "public"."notification_status" AS ENUM('pending', 'processing', 'retryable', 'sent', 'failed');--> statement-breakpoint
CREATE TABLE "admin_notes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"inquiry_id" uuid NOT NULL,
	"author_identifier" varchar(254) NOT NULL,
	"content" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "admin_notes_content_length" CHECK (char_length("admin_notes"."content") between 1 and 10000)
);
--> statement-breakpoint
CREATE TABLE "inquiries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"status" "inquiry_status" DEFAULT 'received' NOT NULL,
	"name" varchar(100) NOT NULL,
	"email" varchar(254) NOT NULL,
	"company" varchar(160) DEFAULT '' NOT NULL,
	"service" varchar(16) NOT NULL,
	"system" text NOT NULL,
	"objective" text NOT NULL,
	"environment" varchar(16) NOT NULL,
	"authority" varchar(16) NOT NULL,
	"protection" varchar(16) DEFAULT 'unknown' NOT NULL,
	"provider" varchar(160) DEFAULT '' NOT NULL,
	"notes" text DEFAULT '' NOT NULL,
	"submission_token" varchar(43) NOT NULL,
	"payload_fingerprint" varchar(64) NOT NULL,
	"archived_at" timestamp with time zone,
	CONSTRAINT "inquiries_submission_token_unique" UNIQUE("submission_token"),
	CONSTRAINT "inquiries_name_nonempty" CHECK (char_length("inquiries"."name") > 0),
	CONSTRAINT "inquiries_system_length" CHECK (char_length("inquiries"."system") between 1 and 1000),
	CONSTRAINT "inquiries_objective_length" CHECK (char_length("inquiries"."objective") between 1 and 2000),
	CONSTRAINT "inquiries_notes_length" CHECK (char_length("inquiries"."notes") <= 2000),
	CONSTRAINT "inquiries_service_valid" CHECK ("inquiries"."service" in ('web', 'network', 'protection', 'unsure')),
	CONSTRAINT "inquiries_environment_valid" CHECK ("inquiries"."environment" in ('production', 'staging', 'multiple', 'unknown')),
	CONSTRAINT "inquiries_authority_valid" CHECK ("inquiries"."authority" in ('owner', 'authorized', 'uncertain')),
	CONSTRAINT "inquiries_protection_valid" CHECK ("inquiries"."protection" in ('unknown', 'none', 'using')),
	CONSTRAINT "inquiries_submission_token_format" CHECK ("inquiries"."submission_token" ~ '^[A-Za-z0-9_-]{43}$'),
	CONSTRAINT "inquiries_payload_fingerprint_format" CHECK ("inquiries"."payload_fingerprint" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
CREATE TABLE "inquiry_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"inquiry_id" uuid NOT NULL,
	"event_type" "inquiry_event_type" NOT NULL,
	"actor_type" "inquiry_actor_type" NOT NULL,
	"actor_identifier" varchar(254),
	"metadata" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "inquiry_events_actor_identifier" CHECK (("inquiry_events"."actor_type" = 'system' and "inquiry_events"."actor_identifier" is null) or ("inquiry_events"."actor_type" = 'admin' and char_length("inquiry_events"."actor_identifier") > 0)),
	CONSTRAINT "inquiry_events_metadata_small_object" CHECK ("inquiry_events"."metadata" is null or (jsonb_typeof("inquiry_events"."metadata") = 'object' and pg_column_size("inquiry_events"."metadata") <= 8192))
);
--> statement-breakpoint
CREATE TABLE "notification_outbox" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"inquiry_id" uuid NOT NULL,
	"event_type" "inquiry_event_type" NOT NULL,
	"status" "notification_status" DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"available_at" timestamp with time zone DEFAULT now() NOT NULL,
	"locked_until" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"sent_at" timestamp with time zone,
	"last_error_code" varchar(100),
	CONSTRAINT "notification_outbox_attempts_nonnegative" CHECK ("notification_outbox"."attempts" >= 0)
);
--> statement-breakpoint
ALTER TABLE "admin_notes" ADD CONSTRAINT "admin_notes_inquiry_id_inquiries_id_fk" FOREIGN KEY ("inquiry_id") REFERENCES "public"."inquiries"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "inquiry_events" ADD CONSTRAINT "inquiry_events_inquiry_id_inquiries_id_fk" FOREIGN KEY ("inquiry_id") REFERENCES "public"."inquiries"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_outbox" ADD CONSTRAINT "notification_outbox_inquiry_id_inquiries_id_fk" FOREIGN KEY ("inquiry_id") REFERENCES "public"."inquiries"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "admin_notes_inquiry_created_idx" ON "admin_notes" USING btree ("inquiry_id","created_at");--> statement-breakpoint
CREATE INDEX "inquiry_events_inquiry_created_idx" ON "inquiry_events" USING btree ("inquiry_id","created_at");--> statement-breakpoint
CREATE INDEX "notification_outbox_claim_idx" ON "notification_outbox" USING btree ("available_at","locked_until") WHERE "notification_outbox"."status" in ('pending', 'retryable');--> statement-breakpoint
CREATE INDEX "notification_outbox_processing_lease_idx" ON "notification_outbox" USING btree ("locked_until") WHERE "notification_outbox"."status" = 'processing';--> statement-breakpoint
CREATE INDEX "notification_outbox_inquiry_idx" ON "notification_outbox" USING btree ("inquiry_id");
--> statement-breakpoint
CREATE FUNCTION reject_inquiry_event_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'inquiry_events is append-only' USING ERRCODE = '55000';
END;
$$;
--> statement-breakpoint
CREATE TRIGGER inquiry_events_append_only BEFORE UPDATE OR DELETE ON "inquiry_events"
FOR EACH ROW EXECUTE FUNCTION reject_inquiry_event_mutation();
