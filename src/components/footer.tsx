import { PublicLink } from "./public-link";
import { Container } from "./container";

export function Footer() {
  return (
    <footer className="site-footer">
      <Container>
        <nav className="footer-primary" aria-label="Alt gezinme">
          <PublicLink href="/#hizmetler">Hizmetler</PublicLink>
          <PublicLink href="/#surec">Nasıl Çalışır</PublicLink>
          <PublicLink href="/#metodoloji">Yöntem ve Sonuçlar</PublicLink>
          <PublicLink href="/#iletisim">İletişim</PublicLink>
        </nav>
        <nav className="footer-secondary" aria-label="Bilgilendirme">
          <PublicLink href="/gizlilik">Gizlilik</PublicLink>
          <PublicLink href="/test-yetkilendirmesi">Test Yetkilendirmesi ve Koşulları</PublicLink>
        </nav>
        <p className="helper copy-width">Testler yalnızca talep sahibine ait veya test için açıkça yetkilendirildiği sistemlerde, kapsam ve izinler belgelendikten sonra yürütülür.</p>
      </Container>
    </footer>
  );
}
