"use client";

import Link from "next/link";
import { useActionState, useEffect, useRef, useState, useTransition } from "react";
import { unstable_rethrow } from "next/navigation";
import { submitTestRequest } from "@/app/test-talep-et/actions";
import { fieldLabels, fieldLimits, getFieldErrors, readRequestFormData, requestSchema, type FieldErrors, type RequestField, type RequestState } from "@/lib/request-schema";
import { serviceOptions } from "@/lib/services";
import { FormField } from "./form-field";
import { Disclosure } from "./disclosure";

const authorityOptions = [
  { value: "owner", label: "Sistem bana / temsil ettiğim kuruluşa ait." },
  { value: "authorized", label: "Sistem sahibinden test için açık yetkim var." },
  { value: "uncertain", label: "Henüz test yetkim yok / yetkimden emin değilim." },
];
const initialState: RequestState = { errors: {} };

export function RequestForm({ initialService }: { initialService: string }) {
  // Retain the native Server Action for submissions before hydration/without JS.
  const [serverState, formAction, serverPending] = useActionState(submitTestRequest, initialState);
  const [clientState, setClientState] = useState<RequestState | null>(null);
  const state = clientState ?? serverState;
  const [values, setValues] = useState(() => ({ name: "", email: "", company: "", service: initialService, system: "", objective: "", environment: "", authority: "", protection: "unknown", provider: "", notes: "", ...serverState.values }));
  const [clientPending, startTransition] = useTransition();
  const pending = clientPending || serverPending;
  const submittingRef = useRef(false);
  const [clientErrors, setClientErrors] = useState<FieldErrors | null>(null);
  const [validationAttempt, setValidationAttempt] = useState(0);
  const summaryRef = useRef<HTMLDivElement>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const errors = clientErrors ?? state.errors;
  const hasErrors = Object.keys(errors).length > 0;

  useEffect(() => {
    if (hasErrors || state.message) summaryRef.current?.focus();
  }, [state, validationAttempt, hasErrors]);

  const update = (field: RequestField, value: string) => setValues((previous) => ({ ...previous, [field]: value }));
  function inputProps(field: RequestField, hasHelper = false) {
    const descriptions = [hasHelper ? `${field}-help` : "", errors[field] ? `${field}-error` : ""].filter(Boolean).join(" ");
    return { id: field, name: field, value: values[field], "aria-invalid": errors[field] ? true : undefined, "aria-describedby": descriptions || undefined, onChange: (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => update(field, event.target.value) };
  }
  function focusField(field: string) {
    const element = document.getElementById(field);
    element?.closest("details")?.setAttribute("open", "");
    if (element instanceof HTMLFieldSetElement) element.querySelector("input")?.focus();
    else element?.focus();
  }

  return (
    <form ref={formRef} className="request-form" action={formAction} noValidate onSubmit={(event) => {
      // Handle hydrated submissions explicitly: React's automatic form reset also
      // runs for returned validation errors, and transport errors must stay inline.
      event.preventDefault();
      if (pending || submittingRef.current) return;
      const data = new FormData(event.currentTarget);
      const result = requestSchema.safeParse(readRequestFormData(data));
      if (!result.success) {
        setClientErrors(getFieldErrors(result.error));
        setValidationAttempt((attempt) => attempt + 1);
        return;
      }
      setClientErrors(null);
      submittingRef.current = true;
      startTransition(async () => {
        try {
          setClientState(await submitTestRequest(initialState, data));
        } catch (error) {
          // Preserve Next.js redirect/not-found control flow; handle transport failures.
          unstable_rethrow(error);
          setClientState({ errors: {}, message: "Talebiniz iletilemedi. Bilgileriniz bu sayfada duruyor; lütfen tekrar deneyin." });
        } finally {
          submittingRef.current = false;
        }
      });
    }}>
      {(hasErrors || state.message) && <div className="error-summary" tabIndex={-1} ref={summaryRef} role="alert">
        <h2>{hasErrors ? "Lütfen işaretli alanları kontrol edin." : "Talep gönderilemedi."}</h2>
        {state.message && <p>{state.message}</p>}
        {hasErrors && <ul>{(Object.entries(errors) as [RequestField, string][]).map(([field, message]) => <li key={field}><a href={`#${field}`} onClick={(event) => { event.preventDefault(); focusField(field); }}>{fieldLabels[field]}: {message}</a></li>)}</ul>}
      </div>}

      <div className="form-grid">
        <FormField id="name" label={fieldLabels.name} error={errors.name}>
          <input {...inputProps("name")} type="text" required maxLength={fieldLimits.name} autoComplete="name" />
        </FormField>
        <FormField id="email" label={fieldLabels.email} error={errors.email} helper="Talebinizle ilgili iletişim için bu adresi kullanacağız.">
          <input {...inputProps("email", true)} type="email" required maxLength={fieldLimits.email} autoComplete="email" autoCapitalize="none" spellCheck={false} />
        </FormField>
        <FormField id="company" label={fieldLabels.company} optional error={errors.company} full>
          <input {...inputProps("company")} type="text" maxLength={fieldLimits.company} autoComplete="organization" />
        </FormField>
        <FormField id="service" label={fieldLabels.service} error={errors.service} full>
          <select {...inputProps("service")} required>{serviceOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select>
        </FormField>
        <FormField id="system" label={fieldLabels.system} error={errors.system} full helper={<>
          <p>Alan adı, IP adresi veya kısa bir açıklama yeterli. Bu bilgi önerilen hedeftir; nihai yetkilendirilmiş kapsam değildir. En fazla 1000 karakter.</p>
          <p>Parola, API anahtarı, özel anahtar, erişim belirteci, yönetici erişim bilgisi veya özel erişim bağlantısı göndermeyin.</p>
        </>}>
          <textarea {...inputProps("system", true)} required maxLength={fieldLimits.system} rows={3} />
        </FormField>
        <FormField id="objective" label={fieldLabels.objective} error={errors.objective} full helper="Cevap aradığınız soruyu kendi kelimelerinizle anlatabilirsiniz. En fazla 2000 karakter.">
          <textarea {...inputProps("objective", true)} required maxLength={fieldLimits.objective} rows={4} />
        </FormField>
        <FormField id="environment" label={fieldLabels.environment} error={errors.environment} full>
          <select {...inputProps("environment")} required>
            <option value="" disabled>Ortam seçin</option>
            <option value="production">Canlı ortam — kullanıcıların eriştiği sistem</option>
            <option value="staging">Test / hazırlık ortamı</option>
            <option value="multiple">Birden fazla ortam</option>
            <option value="unknown">Bilmiyorum</option>
          </select>
        </FormField>
        <fieldset className="form-field field-full" id="authority" role="radiogroup" aria-invalid={errors.authority ? true : undefined} aria-describedby={`authority-help${errors.authority ? " authority-error" : ""}`}>
          <legend>{fieldLabels.authority}</legend>
          <div className="radio-options">{authorityOptions.map((option) => <label className="radio-option" key={option.value}>
            <input type="radio" name="authority" value={option.value} required checked={values.authority === option.value} onChange={(event) => update("authority", event.target.value)} aria-describedby={errors.authority ? "authority-error" : undefined} />
            <span>{option.label}</span>
          </label>)}</div>
          <p className="helper" id="authority-help">Bu beyan yalnızca yetki durumunuzu anlamak içindir; test yürütme izni değildir.</p>
          {errors.authority && <p className="field-error" id="authority-error">{errors.authority}</p>}
          {values.authority === "uncertain" && <p className="context-note" role="status">Talebinizi yine de gönderebilirsiniz. Yetki durumunu birlikte netleştirebiliriz. Gerekli izinler sağlanıp açık yetkilendirme belgelenmeden test yapılamaz.</p>}
        </fieldset>
      </div>

      <Disclosure className="form-extras" label="Ek bilgi ekle (isteğe bağlı)">
        <FormField id="protection" label={fieldLabels.protection} optional error={errors.protection}>
          <select {...inputProps("protection")}>
            <option value="unknown">Bilmiyorum</option><option value="none">Bildiğim bir koruma yok</option><option value="using">Koruma kullanıyorum</option>
          </select>
        </FormField>
        {values.protection === "using" && <FormField id="provider" label={fieldLabels.provider} optional error={errors.provider}>
          <input {...inputProps("provider")} type="text" maxLength={fieldLimits.provider} />
        </FormField>}
        <FormField id="notes" label={fieldLabels.notes} optional error={errors.notes} helper="En fazla 2000 karakter. Gizli erişim bilgileri paylaşmayın.">
          <textarea {...inputProps("notes", true)} maxLength={fieldLimits.notes} rows={4} />
        </FormField>
      </Disclosure>

      <div className="form-privacy">
        <p className="helper">Paylaştığınız bilgiler, talebinizi değerlendirmek ve sizinle iletişime geçmek için kullanılır. Ayrıntılar için <Link href="/gizlilik">Gizlilik sayfasını</Link> inceleyin.</p>
        <p className="helper">Talep göndermek test başlatmaz ve test yürütme yetkisi vermez. Nihai hedefler, kapsam, kapsam dışı alanlar, takvim, sınırlar, durdurma koşulları ve açık yetkilendirme testten önce manuel olarak belgelenir. <Link href="/test-yetkilendirmesi">Test Yetkilendirmesi ve Koşulları</Link>.</p>
      </div>
      <button className="button button-primary" type="submit" disabled={pending}>{pending ? "Gönderiliyor…" : "Talebi Gönder"}</button>
      <span className="sr-only" role="status">{pending ? "Talebiniz işleniyor. Lütfen bekleyin." : ""}</span>
    </form>
  );
}
