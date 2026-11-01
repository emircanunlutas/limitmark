import { handlePublicInquiry } from "@/lib/public-inquiry-handler.server";
import { handleLaboratoryPublicInquiry } from "@/lib/public-inquiry-runtime.server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  if (process.env.LIMITMARK_RUNTIME === "cloud-run-lab") {
    return handleLaboratoryPublicInquiry(request, process.env);
  }
  return handlePublicInquiry(request, { environment: process.env });
}
