import { siteConfig } from "@/lib/site-config";

export function ContactLink({ className, prefix }: { className?: string; prefix?: string }) {
  if (!siteConfig.contactEmail) return null;

  const link = <a className="text-link" href={`mailto:${siteConfig.contactEmail}`}>E-posta ile İletişime Geç</a>;

  // Keep contextual copy and spacing conditional on a usable destination too.
  return className || prefix ? (
    <div className={className}>{prefix && <span>{prefix} </span>}{link}</div>
  ) : link;
}
