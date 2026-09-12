import type { Metadata } from "next";
import Link from "next/link";
import { Container } from "@/components/container";
import { requireAdmin } from "@/lib/admin-auth";
import type { AuthorizedAdminIdentity } from "@/lib/admin-auth-core";
import { getAdminInquiryReadRepository } from "@/lib/admin-inquiry-data";
import { adminInquiryStatuses, buildAdminInquiryHref, normalizeAdminInquiryQuery, type AdminInquiryQuery } from "@/lib/admin-inquiry-query";
import type { AdminInquiryReadRepository } from "@/lib/admin-inquiry-repository";

export const metadata: Metadata = {
  title: "Admin inquiries",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

type AdminSearchParams = Promise<{ page?: string | string[]; status?: string | string[]; q?: string | string[]; mutation?: string | string[] }>;
const labels: Record<string, string> = {
  received: "Received", in_review: "In review", awaiting_scope: "Awaiting scope", proposal_sent: "Proposal sent",
  approved: "Approved", completed: "Completed", declined: "Declined", archived: "Archived",
  web: "Web application", network: "Network / server", protection: "Protection layer", unsure: "Not sure",
  production: "Production", staging: "Staging", multiple: "Multiple", unknown: "Unknown",
};
function displayLabel(value: string): string { return labels[value] ?? value.replaceAll("_", " "); }
function formatTimestamp(value: Date): string {
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Istanbul" }).format(value);
}

async function InquiryList({ query, repository }: { query: AdminInquiryQuery; repository: AdminInquiryReadRepository }) {
  const result = await repository.listInquiries(query);
  if (!result.items.length) return <div className="admin-empty"><h2>No inquiries found</h2><p>No inquiries match the current view.</p></div>;
  return <>
    <div className="admin-table-wrap"><table className="admin-table">
      <caption className="sr-only">Inquiry results, newest first</caption>
      <thead><tr><th scope="col">Received</th><th scope="col">Status</th><th scope="col">Contact</th><th scope="col">Company</th><th scope="col">Service</th><th scope="col">Environment</th><th scope="col"><span className="sr-only">Open</span></th></tr></thead>
      <tbody>{result.items.map((inquiry) => <tr key={inquiry.id}>
        <td><time dateTime={inquiry.receivedAt.toISOString()}>{formatTimestamp(inquiry.receivedAt)}</time></td>
        <td><span className="admin-status">{displayLabel(inquiry.status)}</span></td>
        <td><strong>{inquiry.name}</strong><span>{inquiry.email}</span></td>
        <td>{inquiry.company || <span className="admin-muted">Not provided</span>}</td>
        <td>{displayLabel(inquiry.service)}</td><td>{displayLabel(inquiry.environment)}</td>
        <td><Link className="text-link" href={`/admin/inquiries/${inquiry.id}`} prefetch={false} aria-label={`Open inquiry ${inquiry.id}`}>Open</Link></td>
      </tr>)}</tbody>
    </table></div>
    <nav className="admin-pagination" aria-label="Inquiry pagination">
      {query.page > 1 ? <Link className="button button-secondary" href={buildAdminInquiryHref({ ...query, page: query.page - 1 })}>Previous</Link> : <span />}
      <span>Page {query.page}</span>
      {result.hasNextPage ? <Link className="button button-secondary" href={buildAdminInquiryHref({ ...query, page: query.page + 1 })}>Next</Link> : <span />}
    </nav>
  </>;
}

export async function renderAdminInquiryList(
  searchParams: AdminSearchParams,
  authorize: () => Promise<AuthorizedAdminIdentity> = requireAdmin,
  getRepository: () => Promise<AdminInquiryReadRepository | null> = getAdminInquiryReadRepository,
) {
  await authorize();
  const rawSearchParams = await searchParams;
  const query = normalizeAdminInquiryQuery(rawSearchParams);
  const mutationValue = rawSearchParams.mutation;
  const invalidMutation = mutationValue === "invalid";
  const repository = await getRepository();
  let content: React.ReactNode;
  if (!repository) {
    content = <div className="admin-outage" role="status"><h2>Inquiry data unavailable</h2><p>The inquiry store is not configured or cannot be reached. Try again later.</p></div>;
  } else {
    try { content = await InquiryList({ query, repository }); }
    catch { content = <div className="admin-outage" role="status"><h2>Inquiry data unavailable</h2><p>The inquiry store is not configured or cannot be reached. Try again later.</p></div>; }
  }

  return (
    <div className="page-shell admin-shell"><Container>
      <header className="admin-heading"><p className="admin-eyebrow">Limitmark Admin</p><h1>Inquiries</h1><p>Controlled inquiry administration.</p></header>
      {invalidMutation && <p className="admin-notice admin-notice-warning" role="status">Nothing changed because that operation is not valid.</p>}
      <form className="admin-filters" action="/admin" method="get" role="search">
        <label><span>Search</span><input type="search" name="q" defaultValue={query.search} maxLength={254} placeholder="ID, name, email, or company" /></label>
        <label><span>Status</span><select name="status" defaultValue={query.status ?? ""}><option value="">All statuses</option>{adminInquiryStatuses.map((status) => <option value={status} key={status}>{displayLabel(status)}</option>)}</select></label>
        <button className="button button-primary" type="submit">Apply</button>
        {(query.search || query.status) && <Link className="text-link" href="/admin">Clear</Link>}
      </form>
      {content}
    </Container></div>
  );
}

export default async function AdminPage({ searchParams }: { searchParams: AdminSearchParams }) {
  return renderAdminInquiryList(searchParams);
}
