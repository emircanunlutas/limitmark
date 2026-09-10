import { siteConfig } from "@/lib/site-config";

export function ContactLink() {
  if (siteConfig.contactEmail) {
    return <a className="text-link" href={`mailto:${siteConfig.contactEmail}`}>E-posta ile İletişime Geç</a>;
  }
  return (
    <span className="contact-unavailable">
      <span className="text-link" role="link" aria-disabled="true">E-posta ile İletişime Geç</span>
      <span className="helper">E-posta iletişim adresi henüz paylaşılmadı.</span>
    </span>
  );
}
