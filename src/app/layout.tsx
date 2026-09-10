import type { Metadata } from "next";
import { Header } from "@/components/header";
import { Footer } from "@/components/footer";
import { siteConfig } from "@/lib/site-config";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Kontrollü Dayanıklılık Testleri | Resilience Testing", template: "%s | Resilience Testing" },
  description: "Web uygulaması, sunucu ve koruma katmanları için birlikte kapsamlandırılan, manuel yürütülen ve ölçümlerle raporlanan dayanıklılık testleri.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="tr">
      <body>
        <a className="skip-link" href="#ana-icerik">İçeriğe geç</a>
        <Header name={siteConfig.name} />
        <main id="ana-icerik" tabIndex={-1}>{children}</main>
        <Footer />
      </body>
    </html>
  );
}
