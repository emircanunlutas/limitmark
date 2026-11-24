import type { Metadata } from "next";
import Link from "next/link";
import { AdminFieldHealth } from "@/components/admin-field-health";
import { Container } from "@/components/container";
import { requireAdmin } from "@/lib/admin-auth";

export const metadata: Metadata = { title: "Defense field health", robots: { index: false, follow: false } };
export const dynamic = "force-dynamic";

export default async function FieldHealthPage() {
  await requireAdmin();
  return <div className="page-shell admin-shell"><Container>
    <Link className="text-link" href="/admin" prefetch={false}>Back to inquiries</Link>
    <header className="admin-detail-heading"><h1>Defense field health</h1>
      <p>Review how the defense plane, origin boundary, and synthetic protected app handled requests in a recorded field run.</p>
    </header>
    <AdminFieldHealth />
  </Container></div>;
}
