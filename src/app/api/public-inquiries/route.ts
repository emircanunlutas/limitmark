import { handlePublicInquiry } from "@/lib/public-inquiry-handler.server";
import { handleLaboratoryPublicInquiry } from "@/lib/public-inquiry-runtime.server";
import { createProductionRuntimeDependencies } from "@/lib/public-inquiry-production-runtime.server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  if (process.env.LIMITMARK_RUNTIME === "cloud-run-lab") {
    return handleLaboratoryPublicInquiry(request, process.env);
  }
  // Production: the validated production dependencies, or (disabled by the launch registry/configuration) the unchanged environment-only call,
  // which the handler answers with its generic 503 in persistent mode.
  const production = await createProductionRuntimeDependencies(process.env);
  return handlePublicInquiry(request, production.enabled ? production.dependencies : { environment: process.env });
}
