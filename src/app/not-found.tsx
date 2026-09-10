import { Container } from "@/components/container";
import { ButtonLink } from "@/components/button-link";

export default function NotFound() {
  return <div className="page-shell"><Container><div className="support-page">
    <h1>Sayfa bulunamadı.</h1><p>Bağlantı değişmiş olabilir. Hizmetleri incelemek veya test talebi oluşturmak için ana sayfaya dönebilirsiniz.</p>
    <ButtonLink href="/" variant="text">Ana Sayfaya Dön</ButtonLink>
  </div></Container></div>;
}
