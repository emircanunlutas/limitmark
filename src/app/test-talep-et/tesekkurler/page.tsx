import type { Metadata } from "next";
import { Container } from "@/components/container";
import { ButtonLink } from "@/components/button-link";
import { ContactLink } from "@/components/contact-link";

export const metadata: Metadata = { title: "Talebinizi aldık", robots: { index: false, follow: false } };

export default function ConfirmationPage() {
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
    <div className="confirmation-contact"><span>Bir düzeltme veya ek bilgi için: </span><ContactLink /></div>
  </div></Container></div>;
}
