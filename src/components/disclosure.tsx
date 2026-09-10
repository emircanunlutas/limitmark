import type { ReactNode } from "react";

export function Disclosure({ label, openLabel, children, className = "" }: {
  label: string; openLabel?: string; children: ReactNode; className?: string;
}) {
  return (
    <details className={`disclosure ${className}`.trim()}>
      <summary>
        {openLabel ? <span><span className="disclosure-closed-label">{label}</span><span className="disclosure-open-label">{openLabel}</span></span> : <span>{label}</span>}
        <span className="disclosure-symbol" aria-hidden="true" />
      </summary>
      <div className="disclosure-content">{children}</div>
    </details>
  );
}
