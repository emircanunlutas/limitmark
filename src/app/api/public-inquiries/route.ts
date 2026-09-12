import { handlePublicInquiry } from "@/lib/public-inquiry-handler.server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  // I1 intentionally wires no live OIDC/admission/DB constructors. This keeps
  // Production persistence impossible until a later provider configuration phase.
  return handlePublicInquiry(request, { environment: process.env });
}
