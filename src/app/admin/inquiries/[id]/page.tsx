import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Container } from "@/components/container";
import { requireAdmin } from "@/lib/admin-auth";
import type { AuthorizedAdminIdentity } from "@/lib/admin-auth-core";
import { getAdminInquiryReadRepository } from "@/lib/admin-inquiry-data";
import type { AdminInquiryDetail, AdminInquiryEvent, AdminInquiryReadRepository } from "@/lib/admin-inquiry-repository";
import { allowedInquiryStatusTransitions, type InquiryStatus } from "@/lib/inquiry-status-workflow";
import { addInquiryNoteAction, archiveInquiryAction, changeInquiryStatusAction, restoreInquiryAction } from "../actions";

export const metadata: Metadata = { title: "Admin inquiry detail", robots: { index: false, follow: false } };
export const dynamic = "force-dynamic";
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const statusLabels: Record<string, string> = { received: "Received", in_review: "In review", awaiting_scope: "Awaiting scope", proposal_sent: "Proposal sent", approved: "Approved", completed: "Completed", declined: "Declined", archived: "Archived" };
const mutationNotices: Record<string, { tone: string; message: string }> = {
  success: { tone: "admin-notice-success", message: "Change saved." },
  conflict: { tone: "admin-notice-warning", message: "Nothing changed because this inquiry was updated elsewhere. Review the refreshed record and try again." },
  invalid: { tone: "admin-notice-warning", message: "Nothing changed because that operation is not valid." },
  unavailable: { tone: "admin-notice-warning", message: "The save outcome could not be confirmed. Review the refreshed record and event history before trying again." },
};
function displayStatus(value: string): string { return statusLabels[value] ?? value.replaceAll("_", " "); }
function timestamp(value: Date): string { return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Istanbul" }).format(value); }
function valueOrNotProvided(value: string) { return value || <span className="admin-muted">Not provided</span>; }

export function eventDescription(event: AdminInquiryEvent): string {
  if (event.eventType === "note_added") return "Internal note added";
  if (event.detail?.kind === "status_changed") return `Status changed: ${displayStatus(event.detail.previousStatus)} → ${displayStatus(event.detail.newStatus)}`;
  if (event.detail?.kind === "archived") return `Archived from ${displayStatus(event.detail.previousStatus)}`;
  if (event.detail?.kind === "restored") return `Restored to ${displayStatus(event.detail.restoredStatus)}`;
  const known: Record<string, string> = { inquiry_received: "Inquiry received", status_changed: "Status changed", archived: "Inquiry archived", restored: "Inquiry restored", notification_sent: "Notification sent", notification_failed: "Notification failed" };
  return known[event.eventType] ?? "Activity recorded";
}

function MutationTargetFields({ detail }: { detail: AdminInquiryDetail }) {
  return <><input type="hidden" name="inquiryId" value={detail.inquiry.id} /><input type="hidden" name="expectedRevision" value={detail.inquiry.revision} /></>;
}

function InquiryMutationControls({ detail }: { detail: AdminInquiryDetail }) {
  const nextStatuses = allowedInquiryStatusTransitions(detail.inquiry.status);
  return <section className="admin-panel" aria-labelledby="actions-heading"><h2 id="actions-heading">Admin actions</h2><p className="admin-section-intro">Each action uses revision {detail.inquiry.revision}. Concurrent changes are rejected.</p><div className="admin-action-grid">
    {detail.inquiry.status !== "archived" && nextStatuses.length > 0 && <form action={changeInquiryStatusAction} className="admin-action-form"><h3>Change status</h3><MutationTargetFields detail={detail} /><label htmlFor="new-status">Permitted next status</label><select id="new-status" name="newStatus" required defaultValue={nextStatuses[0]}>{nextStatuses.map((status: InquiryStatus) => <option key={status} value={status}>{displayStatus(status)}</option>)}</select><button className="button button-primary" type="submit">Change status</button></form>}
    {detail.inquiry.status === "archived" ? <div className="admin-action-form"><h3>Restore inquiry</h3>{detail.inquiry.preArchiveStatus ? <form action={restoreInquiryAction}><MutationTargetFields detail={detail} /><p>Restore to <strong>{displayStatus(detail.inquiry.preArchiveStatus)}</strong>.</p><button className="button button-secondary" type="submit">Restore inquiry</button></form> : <p className="admin-muted">This legacy archive has no verified prior status and cannot be restored safely.</p>}</div> : <form action={archiveInquiryAction} className="admin-action-form"><h3>Archive inquiry</h3><MutationTargetFields detail={detail} /><label className="admin-confirm"><input type="checkbox" name="confirmArchive" value="archive" required /> I understand this removes the inquiry from the active workflow.</label><button className="button button-secondary" type="submit">Archive inquiry</button></form>}
  </div></section>;
}

function InquiryDetailView({ detail }: { detail: AdminInquiryDetail }) {
  const fields = [["Reference", detail.inquiry.id], ["Received", timestamp(detail.inquiry.receivedAt)], ["Status", displayStatus(detail.inquiry.status)], ["Name", detail.inquiry.name], ["Email", detail.inquiry.email], ["Company", detail.inquiry.company], ["Service", detail.inquiry.service], ["Environment", detail.inquiry.environment], ["Authority", detail.inquiry.authority], ["Protection", detail.inquiry.protection], ["Provider", detail.inquiry.provider]] as const;
  return <>
    <section className="admin-panel" aria-labelledby="submitted-heading"><h2 id="submitted-heading">Customer-submitted data</h2><dl className="admin-definition-list">{fields.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{valueOrNotProvided(value)}</dd></div>)}</dl>
      <div className="admin-long-fields"><div><h3>System</h3><p>{detail.inquiry.system}</p></div><div><h3>Objective</h3><p>{detail.inquiry.objective}</p></div><div><h3>Customer-submitted notes</h3><p>{valueOrNotProvided(detail.inquiry.notes)}</p></div></div></section>
    <InquiryMutationControls detail={detail} />
    <section className="admin-panel" aria-labelledby="history-heading"><h2 id="history-heading">Event history</h2><p className="admin-section-intro">Oldest first. Events are append-only.{detail.eventsTruncated && " Showing the 500 most recent events."}</p>{detail.events.length ? <ol className="admin-timeline">{detail.events.map((event) => <li key={event.id}><time dateTime={event.createdAt.toISOString()}>{timestamp(event.createdAt)}</time><strong>{eventDescription(event)}</strong><span>{event.actorType}{event.actorType === "admin" && event.actorIdentifier ? ` · ${event.actorIdentifier}` : ""}</span></li>)}</ol> : <p className="admin-muted admin-neutral-empty">No events recorded.</p>}</section>
    <section className="admin-panel" aria-labelledby="notes-heading"><h2 id="notes-heading">Internal admin notes</h2><p className="admin-section-intro">Plain text, visible only to authorized administrators.</p><form action={addInquiryNoteAction} className="admin-note-form"><MutationTargetFields detail={detail} /><label htmlFor="admin-note">Add internal note</label><textarea id="admin-note" name="content" minLength={1} maxLength={10000} required rows={5} /><button className="button button-primary" type="submit">Add note</button></form>{detail.adminNotesTruncated && <p className="admin-section-intro">Showing the 500 most recent notes, oldest first.</p>}{detail.adminNotes.length ? <ol className="admin-note-list">{detail.adminNotes.map((note) => <li key={note.id}><div><time dateTime={note.createdAt.toISOString()}>{timestamp(note.createdAt)}</time><span>{note.authorIdentifier}</span></div><p>{note.content}</p></li>)}</ol> : <p className="admin-muted admin-neutral-empty">No internal admin notes.</p>}</section>
  </>;
}

type DetailSearchParams = Promise<{ mutation?: string | string[] }>;

export async function renderAdminInquiryDetail(
  params: Promise<{ id: string }>,
  authorize: () => Promise<AuthorizedAdminIdentity> = requireAdmin,
  getRepository: () => Promise<AdminInquiryReadRepository | null> = getAdminInquiryReadRepository,
  searchParams: DetailSearchParams = Promise.resolve({}),
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
  const mutationValue = (await searchParams).mutation;
  const mutation = typeof mutationValue === "string" ? mutationNotices[mutationValue] : undefined;
  return <div className="page-shell admin-shell"><Container><Link className="text-link" href="/admin">Back to inquiries</Link><header className="admin-detail-heading"><p className="admin-eyebrow">Limitmark Admin</p><h1>Inquiry detail</h1></header>{mutation && <p className={`admin-notice ${mutation.tone}`} role="status">{mutation.message}</p>}<InquiryDetailView detail={detail} /></Container></div>;
}

export default async function AdminInquiryPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: DetailSearchParams }) { return renderAdminInquiryDetail(params, requireAdmin, getAdminInquiryReadRepository, searchParams); }
