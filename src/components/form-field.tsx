import type { ReactNode } from "react";

export function FormField({ id, label, optional, helper, error, full = false, children }: {
  id: string; label: string; optional?: boolean; helper?: ReactNode; error?: string; full?: boolean; children: ReactNode;
}) {
  return (
    <div className={`form-field ${full ? "field-full" : ""}`.trim()}>
      <label className="field-label" htmlFor={id}>{label}{optional && <span className="optional-label"> (isteğe bağlı)</span>}</label>
      {children}
      {helper && <div className="helper" id={`${id}-help`}>{helper}</div>}
      {error && <p className="field-error" id={`${id}-error`}>{error}</p>}
    </div>
  );
}
