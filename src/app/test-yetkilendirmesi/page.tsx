import type { Metadata } from "next";
import { Container } from "@/components/container";
import { ButtonLink } from "@/components/button-link";

export const metadata: Metadata = { title: "Test Yetkilendirmesi ve Koşulları" };

export default function AuthorizationPage() {
  return <div className="page-shell"><Container><article className="support-page">
    <h1>Test Yetkilendirmesi ve Koşulları</h1>
    <p>Bu sayfa çalışma ilkelerimizi açıklar; nihai sözleşme veya teste özel yetkilendirme belgesi değildir. Uygulanacak koşullar, testten önce taraflarla ayrıca netleştirilir ve belgelenir.</p>
    <h2>Talep, test izni değildir</h2>
    <p>Form göndermek test başlatmaz, test zamanı ayırmaz ve test yürütme izni vermez. Formdaki yetki seçimi yalnızca ilk değerlendirme içindir. Yetkisinden emin olmayan kişiler de kapsam görüşmesi talep edebilir.</p>
    <h2>Testten önce belgelenecek konular</h2>
    <ul>
      <li>Nihai hedefler ve sistem sahibinin açık test yetkilendirmesi.</li>
      <li>Kapsam, kapsam dışı hedefler ve izin verilen test koşulları.</li>
      <li>Takvim, çalışma sınırları, izleme ve sorumlu iletişim kişileri.</li>
      <li>Durdurma koşulları, durdurma prosedürü ve yeniden değerlendirme süreci.</li>
      <li>Gerekli üçüncü taraf veya altyapı sağlayıcısı izinleri.</li>
    </ul>
    <h2>Yetki ve üçüncü taraf sistemler</h2>
    <p>Yalnızca size ait veya test için açıkça yetkilendirildiğiniz sistemlerde çalışırız. Paylaşımlı altyapı, hosting, CDN veya diğer sağlayıcıların koşulları ayrıca değerlendirilir. Gerekli izinler sağlanmadan test yürütülmez.</p>
    <h2>Manuel ve kontrollü uygulama</h2>
    <p>Testler birlikte kapsamlandırılır ve manuel yürütülür. Web sitesinden test başlatılamaz. Koşullar değişirse kapsam ve izinler yeniden değerlendirilir.</p>
    <h2>Sonuçların sınırları</h2>
    <p>Bulgular yalnızca belgelenen test koşulları için geçerlidir. Her saldırıya dayanıklılık, kusursuz koruma veya tüm koşullarda kesintisiz çalışma garantisi verilmez.</p>
    <ButtonLink href="/test-talep-et" variant="text">Test Kapsamını Görüşelim</ButtonLink>
  </article></Container></div>;
}
