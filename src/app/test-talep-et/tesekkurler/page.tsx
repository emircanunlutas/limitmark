import type { Metadata } from "next";
import { Container } from "@/components/container";
import { ButtonLink } from "@/components/button-link";
import { ContactLink } from "@/components/contact-link";
import { isDemoSubmissionAllowed } from "@/lib/submission-policy";

export const metadata: Metadata = { title: "Test Talebi", robots: { index: false, follow: false } };

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
    <h1>Test Talebi</h1>
    <p>Talebinizin alındığını bu sayfadan doğrulayamıyoruz. Gönderim sonucunu formu gönderdiğiniz sayfada kontrol edebilirsiniz.</p>
    <ButtonLink href="/">Ana Sayfaya Dön</ButtonLink>
    <ContactLink className="confirmation-contact" prefix="İletişim için:" />
  </div></Container></div>;
}
