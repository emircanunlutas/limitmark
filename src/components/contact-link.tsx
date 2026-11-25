import { siteConfig } from "@/lib/site-config";

export function ContactLink({ className, prefix, variant = "text" }: { className?: string; prefix?: string; variant?: "text" | "primary" }) {
  if (!siteConfig.contactEmail) return null;

  const link = <a className={variant === "primary" ? "button button-primary" : "text-link"} href={`mailto:${siteConfig.contactEmail}`}>E-posta ile İletişime Geç</a>;

  // Keep contextual copy and spacing conditional on a usable destination too.
  return className || prefix ? (
    <div className={className}>{prefix && <span>{prefix} </span>}{link}</div>
  ) : link;
}
