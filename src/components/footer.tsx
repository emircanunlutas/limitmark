import Link from "next/link";
import { Container } from "./container";

export function Footer() {
  return (
    <footer className="site-footer">
      <Container>
        <nav className="footer-primary" aria-label="Alt gezinme">
          <Link href="/#hizmetler">Hizmetler</Link>
          <Link href="/#surec">Nasıl Çalışır</Link>
          <Link href="/#metodoloji">Yöntem ve Sonuçlar</Link>
          <Link href="/#iletisim">İletişim</Link>
        </nav>
        <nav className="footer-secondary" aria-label="Bilgilendirme">
          <Link href="/gizlilik">Gizlilik</Link>
          <Link href="/test-yetkilendirmesi">Test Yetkilendirmesi ve Koşulları</Link>
        </nav>
        <p className="helper copy-width">Testler yalnızca talep sahibine ait veya test için açıkça yetkilendirildiği sistemlerde, kapsam ve izinler belgelendikten sonra yürütülür.</p>
      </Container>
    </footer>
  );
}
