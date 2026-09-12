import type { Metadata } from "next";
import { Container } from "@/components/container";
import { RequestForm } from "@/components/request-form";
import { resolveService } from "@/lib/services";
import { generateSubmissionToken } from "@/lib/submission-token.server";
import { connection } from "next/server";
import { getPublicIntakeState } from "@/lib/public-submission-config";
import { availableProductionRateLimitProviders } from "@/lib/rate-limit";
import { getContactEmail } from "@/lib/contact-email";

export const metadata: Metadata = { title: "Test Talep Et", description: "Sisteminizi ve öğrenmek istediğiniz konuyu paylaşın. Test kapsamını ve yetkilendirmeyi manuel olarak birlikte belirleyelim." };

export default async function RequestPage({ searchParams }: { searchParams: Promise<{ hizmet?: string | string[] }> }) {
  await connection();
  const { hizmet } = await searchParams;
  const service = resolveService(hizmet);
  const intake = getPublicIntakeState(process.env, availableProductionRateLimitProviders);
  if (intake.kind === "closed") {
    const contactEmail = getContactEmail(process.env.CONTACT_EMAIL);
    return <div className="page-shell"><Container>
      <div className="closed-intake" role="status" aria-labelledby="closed-intake-title">
        <p className="closed-intake-eyebrow">İletişim</p>
        <h1 id="closed-intake-title">Çevrim içi talepler şu anda kullanılamıyor.</h1>
        <p>Bu sayfadan bilgi gönderemezsiniz ve burada hiçbir bilgi kaydedilmez.</p>
        {contactEmail && <>
          <p>Bir test ihtiyacını görüşmek isterseniz, e-posta yoluyla bizimle iletişime geçebilirsiniz.</p>
          <div className="closed-intake-contact"><a className="text-link" href={`mailto:${contactEmail}`}>E-posta ile İletişime Geç</a></div>
        </>}
      </div>
    </Container></div>;
  }
  const submissionToken = generateSubmissionToken();
  const turnstile = intake.kind === "real" ? intake.turnstile : null;
  return <div className="page-shell"><Container>
    <div className="page-heading">
      <h1>Test Talep Et</h1>
      <p>Sisteminizi ve öğrenmek istediğiniz konuyu kısaca anlatın. Talebinizi manuel inceleyip uygun test kapsamını birlikte belirlemek için sizinle iletişime geçelim.</p>
      <p>Teknik ayrıntıları bilmeniz gerekmez. Emin olmadığınız noktaları birlikte netleştirebiliriz.</p>
      <p className="request-notice">Bu formu göndermek test başlatmaz.</p>
      <p className="helper">İsteğe bağlı alanları boş bırakabilirsiniz.</p>
    </div>
    {intake.kind === "demo" && <p className="demo-notice" role="status">Demo akışı: Bu formdaki bilgiler kaydedilmez ve gerçek bir talep oluşturmaz.</p>}
    <RequestForm key={service} initialService={service} submissionToken={submissionToken} turnstile={turnstile} />
  </Container></div>;
}
