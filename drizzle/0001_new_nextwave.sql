ALTER TABLE "inquiries" ADD COLUMN "revision" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "inquiries" ADD COLUMN "pre_archive_status" "inquiry_status";--> statement-breakpoint
ALTER TABLE "inquiries" ADD CONSTRAINT "inquiries_revision_nonnegative" CHECK ("inquiries"."revision" >= 0);--> statement-breakpoint
ALTER TABLE "inquiries" ADD CONSTRAINT "inquiries_pre_archive_status_valid" CHECK ("inquiries"."pre_archive_status" is null or "inquiries"."pre_archive_status" <> 'archived');