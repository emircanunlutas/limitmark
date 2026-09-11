import type { Metadata } from "next";
import { Container } from "@/components/container";
import { RequestForm } from "@/components/request-form";
import { resolveService } from "@/lib/services";
import { generateSubmissionToken } from "@/lib/submission-token.server";
import { connection } from "next/server";
import { getTurnstileClientConfiguration } from "@/lib/public-submission-config";
import { availableProductionRateLimitProviders } from "@/lib/rate-limit";

export const metadata: Metadata = { title: "Test Talep Et", description: "Sisteminizi ve öğrenmek istediğiniz konuyu paylaşın. Test kapsamını ve yetkilendirmeyi manuel olarak birlikte belirleyelim." };

export default async function RequestPage({ searchParams }: { searchParams: Promise<{ hizmet?: string | string[] }> }) {
  await connection();
  const { hizmet } = await searchParams;
  const service = resolveService(hizmet);
  const submissionToken = generateSubmissionToken();
  const turnstile = getTurnstileClientConfiguration(process.env, availableProductionRateLimitProviders);
  return <div className="page-shell"><Container>
    <div className="page-heading">
      <h1>Test Talep Et</h1>
      <p>Sisteminizi ve öğrenmek istediğiniz konuyu kısaca anlatın. Talebinizi manuel inceleyip uygun test kapsamını birlikte belirlemek için sizinle iletişime geçelim.</p>
      <p>Teknik ayrıntıları bilmeniz gerekmez. Emin olmadığınız noktaları birlikte netleştirebiliriz.</p>
      <p className="request-notice">Bu formu göndermek test başlatmaz.</p>
      <p className="helper">İsteğe bağlı alanları boş bırakabilirsiniz.</p>
    </div>
    <RequestForm key={service} initialService={service} submissionToken={submissionToken} turnstile={turnstile} />
  </Container></div>;
}
