import { ButtonLink } from "@/components/button-link";
import { ContactLink } from "@/components/contact-link";
import { Container } from "@/components/container";
import { Disclosure } from "@/components/disclosure";
import { MethodologyDiagram } from "@/components/methodology-diagram";
import { services } from "@/lib/services";

const deliveries = [
  ["Test Koşulları", "Hangi sistemlerin, hangi koşullarda ve hangi sınırlar içinde test edildiğini gösteren kapsam özeti. Hedefler, kapsam dışı alanlar ve testin yorumlanması için gerekli bağlam."],
  ["Ölçülen Davranış", "Kapsama göre erişilebilirlik, bağlantı kurulabilirliği, yanıt davranışı ve ilgili etkiler. Test sırasında gerçekten gözlenen davranışların ölçümlerle aktarımı."],
  ["Bulgular ve Sonraki Adımlar", "Gözlemlerin teknik yorumu, ölçümün sınırları ve olası darboğazlar. Sisteminizi iyileştirmek veya daha ayrıntılı incelemek için uygulanabilir sonraki adımlar."],
];
const steps = [
  ["İhtiyacınızı anlatın", "Sisteminizi ve cevap aradığınız soruyu kısaca paylaşın."],
  ["Kapsamı netleştirelim", "Hedefleri, test koşullarını ve kapsam dışı alanları birlikte belirleyelim."],
  ["Yetkilendirme ve zamanı kesinleştirelim", "Açık izni, takvimi, sınırları ve durdurma prosedürünü belgeleyelim."],
  ["Testi yürütelim", "Kararlaştırılan planı manuel uygulayalım; sistem davranışını izleyelim."],
  ["Sonuçları değerlendirelim", "Ölçümleri, bulguları ve sonraki adımları birlikte ele alalım."],
];
const principles = [
  ["Tanımlı sınırlar", "Hedefler, kapsam dışı alanlar ve test koşulları uygulamadan önce kararlaştırılır. Test, bu sınırlar içinde yürütülür."],
  ["Kontrollü yük", "Sistem, üzerinde anlaşılan test planı içinde kontrollü yük uygulanırken gözlemlenir. İlerleme ve durdurma koşulları önceden belirlenir."],
  ["Gerçek erişimin izlenmesi", "İlgili senaryolarda, yük ve koruma davranışıyla birlikte normal kullanıcıların erişimi de değerlendirilir. Korumanın devrede olması tek başına yeterli bir sonuç değildir."],
  ["Kanıta bağlı yorum", "Yorumlar yalnızca gözlenen ölçümlere ve belgelenen koşullara dayanır. Ölçülemeyen noktalar ve sonuçların sınırları açıkça belirtilir."],
];
const faqs = [
  ["Hangi teste ihtiyacım olduğunu bilmiyorum. Ne yapmalıyım?", "Talep formunda “Karar veremiyorum / birlikte belirleyelim” seçeneğini kullanın. Sisteminizi ve öğrenmek istediğiniz konuyu anlatmanız yeterli. Uygun kapsamı görüşerek netleştirebiliriz."],
  ["Canlı sistem üzerinde test yapılabilir mi?", "Uygunluğu birlikte değerlendirebiliriz. Canlı sistemde test ancak olası etkiler, test zamanı, izleme, sınırlar ve durdurma prosedürü kararlaştırılıp açık yetkilendirme belgelendikten sonra yapılır. Her sistem için uygun olmayabilir."],
  ["Size hangi erişim bilgilerini vermem gerekiyor?", "İlk talep için alan adı, IP adresi veya kısa bir sistem açıklaması yeterlidir. Parola, API anahtarı, özel anahtar, erişim belirteci, yönetici erişim bilgisi veya özel erişim bağlantısı göndermeyin. Gerekli teknik bilgiler kapsam görüşmesinde ayrıca belirlenir."],
  ["Sistemim paylaşımlı hosting, CDN veya başka bir sağlayıcı kullanıyorsa ne olur?", "Sağlayıcının koşulları, ortak altyapıya olası etkiler ve gerekli ek izinler kapsam görüşmesinde değerlendirilir. Sistemin size ait olması, üçüncü taraf altyapısını test etme yetkisi anlamına gelmez. Gerekli izinler netleşmeden test yapılmaz."],
  ["Test sırasında bir sorun oluşursa ne olur?", "İletişim kanalı, sorumlu kişiler ve durdurma koşulları testten önce belirlenir. Kararlaştırılan koşullarda test durdurulur ve durum birlikte değerlendirilir. Yeniden başlama kararı, üzerinde anlaşılan kapsam ve izinler çerçevesinde verilir."],
  ["Testte sorun çıkmaması sistemimin DDoS saldırılarına karşı tamamen güvenli olduğu anlamına gelir mi?", "Hayır. Sonuçlar yalnızca belgelenen test koşullarını açıklar. Sorun gözlenmemesi, her olası saldırıya dayanıklılık veya tüm koşullarda kesintisiz çalışma garantisi değildir."],
  ["Test talebi gönderdiğimde test otomatik olarak başlar mı?", "Hayır. Talep yalnızca kapsam görüşmesini başlatmak içindir; test başlatmaz ve test yürütme izni vermez. Nihai hedefler, kapsam, istisnalar, takvim, sınırlar ve durdurma koşulları ile açık yetkilendirme testten önce manuel olarak belgelenir."],
];

export default function HomePage() {
  return (
    <>
      <section className="hero" aria-labelledby="hero-title">
        <Container className="hero-grid">
          <div className="hero-copy">
            <h1 id="hero-title">Dayanıklılığı varsaymayın.<br />Ölçün.</h1>
            <p className="hero-intro">Web uygulamanızın, sunucunuzun ve koruma katmanlarınızın yoğun trafik ve DDoS koşullarını temsil eden kontrollü yük altında nasıl davrandığını görün.</p>
            <p className="hero-manual">Testleri birlikte kapsamlandırıyor, manuel yürütüyor ve sonuçları ölçümlerle raporluyoruz.</p>
            <div className="hero-actions">
              <ButtonLink href="/test-talep-et">Test Talep Et</ButtonLink>
              <ButtonLink href="#hizmetler" variant="secondary">Hizmetleri İncele</ButtonLink>
            </div>
            <p className="helper hero-authorization">Yalnızca size ait veya test için açıkça yetkilendirildiğiniz sistemlerde çalışıyoruz.</p>
          </div>
          <MethodologyDiagram />
        </Container>
      </section>

      <section id="hizmetler" className="section section-bordered" aria-labelledby="services-title">
        <Container>
          <div className="section-intro">
            <h2 id="services-title">Neyi ölçmek istiyorsunuz?</h2>
            <p>Uygulamanızın, servislerinizin veya koruma katmanlarınızın davranışını inceleyelim. Test kapsamını, cevap aradığınız soruya göre birlikte belirleyelim.</p>
          </div>
          <div className="services-grid">
            {services.map((service) => (
              <article className="service-card" key={service.id}>
                <h3>{service.title}</h3>
                <p className="service-question">{service.question}</p>
                <p className="service-scope">{service.scope}</p>
                <div className="service-result"><h4>Sonuç</h4><p>{service.result}</p></div>
                <ButtonLink variant="text" href={`/test-talep-et?hizmet=${service.id}`} aria-label={`${service.title} — Bu Testi Görüşelim`}>Bu Testi Görüşelim</ButtonLink>
              </article>
            ))}
          </div>
          <p className="service-followup">Hangi hizmetin uygun olduğundan emin değil misiniz? <ButtonLink variant="text" href="/test-talep-et">İhtiyacınızı birlikte belirleyelim.</ButtonLink></p>
        </Container>
      </section>

      <section id="sonuclar" className="section section-bordered" aria-labelledby="deliverables-title">
        <Container>
          <div className="section-intro">
            <h2 id="deliverables-title">Testin sonunda elinizde ne olacak?</h2>
            <p>Yalnızca bir sonuç değil; sonucun hangi koşullarda elde edildiğini ve ne anlama geldiğini açıklayan bir rapor.</p>
          </div>
          <div className="deliveries-grid">{deliveries.map(([title, copy]) => <article className="ruled-block" key={title}><h3>{title}</h3><p>{copy}</p></article>)}</div>
          <p className="limitation copy-width">Bulgular yalnızca belgelenen test koşulları için geçerlidir. Her olası saldırıya karşı dayanıklılık veya tüm koşullarda kesintisiz çalışma garantisi vermez.</p>
          <ButtonLink href="#surec" variant="text">Test Sürecini İncele</ButtonLink>
        </Container>
      </section>

      <section id="surec" className="section section-bordered" aria-labelledby="process-title">
        <Container>
          <div className="section-intro"><h2 id="process-title">Birlikte planlanır.<br />Kontrollü yürütülür.</h2></div>
          <ol className="process-list">{steps.map(([title, copy], index) => (
            <li key={title}>
              <span className="process-number" aria-hidden="true">{String(index + 1).padStart(2, "0")}</span>
              <div><h3>{title}</h3><p>{copy}</p></div>
            </li>
          ))}</ol>
          <p className="process-note copy-width">Talep göndermek test başlatmaz ve test yürütme izni vermez. Uygulamadan önce nihai kapsamın ve açık yetkilendirmenin belgelenmesi gerekir.</p>
        </Container>
      </section>

      <section id="metodoloji" className="section section-bordered" aria-labelledby="methodology-title">
        <Container>
          <div className="section-intro">
            <h2 id="methodology-title">Nasıl ölçtüğümüz açık olmalı.</h2>
            <p>Bir sonucun değeri; neyin, hangi koşullarda test edildiğini ve gerçekte ne gözlendiğini bilmekle başlar. Ölçümü ve yorumu bu bağlamla birlikte sunarız.</p>
          </div>
          <div className="principles-grid">{principles.map(([title, copy]) => <article className="ruled-block" key={title}><h3>{title}</h3><p>{copy}</p></article>)}</div>
          <Disclosure className="technical-disclosure" label="Teknik Kapsamı Gör" openLabel="Teknik Kapsamı Gizle">
            <div className="technical-copy">
              <div><h3>Servis ve bağlantı davranışı</h3><p>Testin amacına göre TCP/UDP servis davranışı, HTTP/HTTPS istekleri ve TLS bağlantı kurulumu incelenebilir. Her yetenek her testte kullanılmaz; uygun senaryolar kapsam görüşmesinde seçilir.</p></div>
              <div><h3>Kullanıcı erişimi</h3><p>İlgili durumlarda tarayıcı tabanlı senaryolarla normal kullanıcı deneyimi ve erişilebilirlik gözlemlenir. Değerlendirilecek akışlar testten önce kararlaştırılır.</p></div>
              <div><h3>İzleme bağlamı</h3><p>Müşterinin isteğe bağlı paylaştığı sunucu, ağ veya koruma katmanı izleme bilgileri sonuçların yorumlanmasına yardımcı olabilir. Genel talep formunda ayrıcalıklı erişim bilgisi istenmez.</p></div>
              <div><h3>Ölçümün sınırları</h3><p>Gözlem noktaları, kullanılan senaryolar ve mevcut izleme bilgileri ölçümün kapsamını etkiler. Teste özgü kısıtlar raporda belirtilir; gözlenmeyen koşullar hakkında kesin sonuç çıkarılmaz.</p></div>
            </div>
          </Disclosure>
        </Container>
      </section>

      <section id="sss" className="section section-bordered" aria-labelledby="faq-title">
        <Container>
          <div className="section-intro"><h2 id="faq-title">Sık sorulan sorular</h2></div>
          <div className="faq-list">{faqs.map(([question, answer]) => <Disclosure className="faq-item" key={question} label={question}><p>{answer}</p></Disclosure>)}</div>
        </Container>
      </section>

      <section id="iletisim" className="section closing-section" aria-labelledby="closing-title">
        <Container>
          <div className="closing-panel">
            <div className="closing-copy">
              <h2 id="closing-title">Altyapınızla ilgili hangi soruya cevap arıyorsunuz?</h2>
              <p>Sisteminizi ve öğrenmek istediğiniz konuyu paylaşın. Uygun test kapsamını birlikte netleştirelim.</p>
              <ButtonLink href="/test-talep-et">Test Talep Et</ButtonLink>
              <ContactLink className="closing-contact" />
            </div>
          </div>
        </Container>
      </section>
    </>
  );
}
