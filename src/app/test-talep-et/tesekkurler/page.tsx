import type { Metadata } from "next";
import { Container } from "@/components/container";
import { ButtonLink } from "@/components/button-link";
import { ContactLink } from "@/components/contact-link";
import { isDemoSubmissionAllowed } from "@/lib/submission-policy";

export const metadata: Metadata = { title: "Talebinizi aldık", robots: { index: false, follow: false } };

export const dynamic = "force-dynamic";

export default function ConfirmationPage() {
  if (isDemoSubmissionAllowed(process.env)) return <div className="page-shell"><Container><div className="confirmation-page">
    <h1>Demo akışı tamamlandı.</h1>
    <p>Bu bir deneme akışıydı. Formdaki bilgiler kaydedilmedi, iletilmedi ve gerçek bir talep oluşturulmadı.</p>
    <p>Gerçek bir test talebi için çevrim içi başvuru kanalının açılmasını bekleyebilir veya yayımlanmış iletişim adresini kullanabilirsiniz.</p>
    <ButtonLink href="/">Ana Sayfaya Dön</ButtonLink>
    <ContactLink className="confirmation-contact" prefix="İletişim için:" />
  </div></Container></div>;
  return <div className="page-shell"><Container><div className="confirmation-page">
    <h1>Talebinizi aldık.</h1>
    <p>Paylaştığınız bilgileri manuel inceleyeceğiz. İhtiyacınızı netleştirmek ve uygun test kapsamını görüşmek için belirttiğiniz e-posta adresinden sizinle iletişime geçeceğiz.</p>
    <h2>Bundan sonra ne olacak?</h2>
    <ol>
      <li>İhtiyacı ve uygunluğu değerlendireceğiz.</li>
      <li>Kapsamı birlikte belirleyeceğiz.</li>
      <li>Testten önce açık yetkilendirmeyi belgeleyeceğiz.</li>
    </ol>
    <div className="confirmation-authorization"><p>Bu başvuru bir test başlatmadı veya test zamanı ayırmadı. Formdaki yetki beyanı, test yürütme izni değildir.</p></div>
    <p>Şu anda başka bir bilgi göndermeniz gerekmiyor. Parola, API anahtarı, özel anahtar, erişim belirteci veya yönetici erişim bilgisi paylaşmayın.</p>
    <ButtonLink href="/">Ana Sayfaya Dön</ButtonLink>
    <ContactLink className="confirmation-contact" prefix="Bir düzeltme veya ek bilgi için:" />
  </div></Container></div>;
}
