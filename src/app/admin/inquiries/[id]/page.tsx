import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Container } from "@/components/container";
import { requireAdmin } from "@/lib/admin-auth";
import type { AuthorizedAdminIdentity } from "@/lib/admin-auth-core";
import { getAdminInquiryReadRepository } from "@/lib/admin-inquiry-data";
import type { AdminInquiryDetail, AdminInquiryReadRepository } from "@/lib/admin-inquiry-repository";

export const metadata: Metadata = { title: "Admin inquiry detail", robots: { index: false, follow: false } };
export const dynamic = "force-dynamic";
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function timestamp(value: Date): string { return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Istanbul" }).format(value); }
function valueOrNotProvided(value: string) { return value || <span className="admin-muted">Not provided</span>; }

function InquiryDetailView({ detail }: { detail: AdminInquiryDetail }) {
  const fields = [["Reference", detail.inquiry.id], ["Received", timestamp(detail.inquiry.receivedAt)], ["Status", detail.inquiry.status], ["Name", detail.inquiry.name], ["Email", detail.inquiry.email], ["Company", detail.inquiry.company], ["Service", detail.inquiry.service], ["Environment", detail.inquiry.environment], ["Authority", detail.inquiry.authority], ["Protection", detail.inquiry.protection], ["Provider", detail.inquiry.provider]] as const;
  return <>
    <section className="admin-panel" aria-labelledby="submitted-heading"><h2 id="submitted-heading">Submitted data</h2><dl className="admin-definition-list">{fields.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{valueOrNotProvided(value)}</dd></div>)}</dl>
      <div className="admin-long-fields"><div><h3>System</h3><p>{detail.inquiry.system}</p></div><div><h3>Objective</h3><p>{detail.inquiry.objective}</p></div><div><h3>Submitted notes</h3><p>{valueOrNotProvided(detail.inquiry.notes)}</p></div></div></section>
    <section className="admin-panel" aria-labelledby="history-heading"><h2 id="history-heading">Event history</h2><p className="admin-section-intro">Oldest first. Events are append-only.{detail.eventsTruncated && " Showing the 500 most recent events."}</p>{detail.events.length ? <ol className="admin-timeline">{detail.events.map((event) => <li key={event.id}><time dateTime={event.createdAt.toISOString()}>{timestamp(event.createdAt)}</time><strong>{event.eventType.replaceAll("_", " ")}</strong><span>{event.actorType}{event.actorType === "admin" && event.actorIdentifier ? ` · ${event.actorIdentifier}` : ""}</span></li>)}</ol> : <p className="admin-muted admin-neutral-empty">No events recorded.</p>}</section>
    <section className="admin-panel" aria-labelledby="notes-heading"><h2 id="notes-heading">Admin notes</h2>{detail.adminNotesTruncated && <p className="admin-section-intro">Showing the 500 most recent notes, oldest first.</p>}{detail.adminNotes.length ? <ol className="admin-note-list">{detail.adminNotes.map((note) => <li key={note.id}><div><time dateTime={note.createdAt.toISOString()}>{timestamp(note.createdAt)}</time><span>{note.authorIdentifier}</span></div><p>{note.content}</p></li>)}</ol> : <p className="admin-muted admin-neutral-empty">No admin notes.</p>}</section>
  </>;
}

export async function renderAdminInquiryDetail(
  params: Promise<{ id: string }>,
  authorize: () => Promise<AuthorizedAdminIdentity> = requireAdmin,
  getRepository: () => Promise<AdminInquiryReadRepository | null> = getAdminInquiryReadRepository,
) {
  await authorize();
  const { id } = await params;
  if (!uuidPattern.test(id)) notFound();
  const repository = await getRepository();
  if (!repository) return <div className="page-shell admin-shell"><Container><Link className="text-link" href="/admin">Back to inquiries</Link><div className="admin-outage" role="status"><h1>Inquiry data unavailable</h1><p>The inquiry store is not configured or cannot be reached. Try again later.</p></div></Container></div>;
  let detail: AdminInquiryDetail | null;
  try { detail = await repository.getInquiryDetail(id); }
  catch { return <div className="page-shell admin-shell"><Container><Link className="text-link" href="/admin">Back to inquiries</Link><div className="admin-outage" role="status"><h1>Inquiry data unavailable</h1><p>The inquiry store is not configured or cannot be reached. Try again later.</p></div></Container></div>; }
  if (!detail) notFound();
  return <div className="page-shell admin-shell"><Container><Link className="text-link" href="/admin">Back to inquiries</Link><header className="admin-detail-heading"><p className="admin-eyebrow">Limitmark Admin</p><h1>Inquiry detail</h1></header><InquiryDetailView detail={detail} /></Container></div>;
}

export default async function AdminInquiryPage({ params }: { params: Promise<{ id: string }> }) { return renderAdminInquiryDetail(params); }
