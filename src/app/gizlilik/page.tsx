import type { Metadata } from "next";
import { Container } from "@/components/container";
import { ButtonLink } from "@/components/button-link";
import { ContactLink } from "@/components/contact-link";

export const metadata: Metadata = { title: "Gizlilik" };

export default function PrivacyPage() {
  return <div className="page-shell"><Container><article className="support-page">
    <h1>Gizlilik</h1>
    <p>Bu sayfa, talep sürecindeki temel gizlilik yaklaşımını açıklar. Nihai gizlilik ve kişisel veri aydınlatma metninin yerini tutmaz; hizmet kullanıma açılmadan önce tamamlanacaktır.</p>
    <h2>Talep için paylaşılan bilgiler</h2>
    <p>Formda adınız, e-posta adresiniz, ilgilendiğiniz hizmet, önerilen sistem, öğrenmek istediğiniz konu, ortam ve yetki durumunuz istenir. Kuruluş, koruma bilgisi ve ek notlar isteğe bağlıdır.</p>
    <h2>Kullanım amacı</h2>
    <p>Talep sürecinde bu bilgiler ihtiyacınızı değerlendirmek, uygun kapsamı görüşmek ve sizinle iletişim kurmak için kullanılır. Formdaki hedef ve yetki beyanı test yürütme izni sayılmaz.</p>
    <h2>Gizli erişim bilgisi paylaşmayın</h2>
    <p>Parola, API anahtarı, özel anahtar, erişim belirteci, yönetici erişim bilgisi veya özel erişim bağlantısı göndermeyin. Talebinizde yalnızca değerlendirme için gerekli bilgileri paylaşın.</p>
    <h2>Site ve dış kaynaklar</h2>
    <p>Bu sürümde reklam veya ziyaretçi analiz aracı kullanılmaz. Inter yazı tipini yüklemek için tarayıcınız Google Fonts hizmetine bağlanabilir; bu bağlantıda IP adresiniz ve tarayıcıya ilişkin teknik bilgiler ilgili hizmete iletilebilir. Yazı tipi yüklenmezse sistem yazı tipi kullanılır.</p>
    <h2>Tamamlanacak bilgiler</h2>
    <p>Veri sorumlusu ve iletişim bilgileri, hukuki dayanaklar, saklama süreleri, hizmet sağlayıcılar ve ilgili kişi başvuru yöntemi nihai metinde açıklanacaktır. Bu bilgiler belirlenmeden gerçek müşteri talepleri alınmaya başlanmayacaktır.</p>
    <ContactLink />
    <ButtonLink href="/test-talep-et" variant="text">Talep Formuna Dön</ButtonLink>
  </article></Container></div>;
}
