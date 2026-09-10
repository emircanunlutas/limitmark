import type { Metadata } from "next";
import { Container } from "@/components/container";
import { RequestForm } from "@/components/request-form";
import { resolveService } from "@/lib/services";

export const metadata: Metadata = { title: "Test Talep Et", description: "Sisteminizi ve öğrenmek istediğiniz konuyu paylaşın. Test kapsamını ve yetkilendirmeyi manuel olarak birlikte belirleyelim." };

export default async function RequestPage({ searchParams }: { searchParams: Promise<{ hizmet?: string | string[] }> }) {
  const { hizmet } = await searchParams;
  const service = resolveService(hizmet);
  return <div className="page-shell"><Container>
    <div className="page-heading">
      <h1>Test Talep Et</h1>
      <p>Sisteminizi ve öğrenmek istediğiniz konuyu kısaca anlatın. Talebinizi manuel inceleyip uygun test kapsamını birlikte belirlemek için sizinle iletişime geçelim.</p>
      <p>Teknik ayrıntıları bilmeniz gerekmez. Emin olmadığınız noktaları birlikte netleştirebiliriz.</p>
      <p className="request-notice">Bu formu göndermek test başlatmaz.</p>
      <p className="helper">İsteğe bağlı alanları boş bırakabilirsiniz.</p>
    </div>
    <RequestForm key={service} initialService={service} />
  </Container></div>;
}
