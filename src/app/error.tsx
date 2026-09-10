"use client";

import { Container } from "@/components/container";
import { ButtonLink } from "@/components/button-link";

export default function ErrorPage({ reset }: { reset: () => void }) {
  return <div className="page-shell"><Container><div className="support-page">
    <h1>Sayfa yüklenemedi.</h1><p>Bir sorun oluştu. Lütfen yeniden deneyin. Bu hata herhangi bir test başlatmaz.</p>
    <div className="hero-actions"><button className="button button-primary" onClick={reset}>Yeniden Dene</button><ButtonLink href="/" variant="secondary">Ana Sayfaya Dön</ButtonLink></div>
  </div></Container></div>;
}
