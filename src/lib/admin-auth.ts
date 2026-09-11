import "server-only";

import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { resolveAdminFromRequest, type AuthorizedAdminIdentity } from "./admin-auth-core";

/** Reusable enforcement boundary for Server Components, Actions, and Route Handlers. */
export async function requireAdmin(): Promise<AuthorizedAdminIdentity> {
  const identity = await resolveAdminFromRequest(await headers(), process.env);
  if (!identity) notFound();
  return identity;
}
