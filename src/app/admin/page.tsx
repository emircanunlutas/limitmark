import type { Metadata } from "next";
import { Container } from "@/components/container";
import { requireAdmin } from "@/lib/admin-auth";
import type { AuthorizedAdminIdentity } from "@/lib/admin-auth-core";

export const metadata: Metadata = {
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

export async function renderAdminSkeleton(
  authorize: () => Promise<AuthorizedAdminIdentity> = requireAdmin,
) {
  await authorize();

  return (
    <div className="page-shell">
      <Container>
        <div className="support-page">
          <h1>Limitmark Admin</h1>
          <p>Authenticated internal access.</p>
        </div>
      </Container>
    </div>
  );
}

export default async function AdminPage() {
  return renderAdminSkeleton();
}
