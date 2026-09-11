import "server-only";

import { getContactEmail } from "./contact-email";

export type AdminAuthEnvironment = {
  [key: string]: string | undefined;
  CLOUDFLARE_ACCESS_TEAM_DOMAIN?: string;
  CLOUDFLARE_ACCESS_AUD?: string;
  ADMIN_ALLOWED_EMAILS?: string;
};

export type AdminAuthConfiguration =
  | {
      enabled: false;
      reason: "team-domain" | "audience" | "allowlist";
    }
  | {
      enabled: true;
      teamDomain: string;
      audience: string;
      allowedEmails: ReadonlySet<string>;
    };

function normalizeTeamDomain(value: string | undefined): string | null {
  const input = value?.trim() ?? "";
  if (!input) return null;

  try {
    const url = new URL(input);
    const hostname = url.hostname.toLowerCase();
    const isTeamHostname = /^(?!-)[a-z0-9-]{1,63}(?<!-)\.cloudflareaccess\.com$/.test(hostname);
    const isOriginOnly =
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.port === "" &&
      url.pathname === "/" &&
      url.search === "" &&
      url.hash === "";

    return isTeamHostname && isOriginOnly ? `https://${hostname}` : null;
  } catch {
    return null;
  }
}

function normalizeAudience(value: string | undefined): string | null {
  const audience = value?.trim() ?? "";
  return /^[A-Za-z0-9_-]{1,512}$/.test(audience) ? audience : null;
}

function normalizeAllowlist(value: string | undefined): ReadonlySet<string> | null {
  if (value === undefined) return null;

  const entries = value.split(",");
  if (entries.length === 0) return null;

  const normalized = new Set<string>();
  for (const entry of entries) {
    const mailbox = getContactEmail(entry);
    if (!mailbox) return null;

    const email = mailbox.toLowerCase();
    if (normalized.has(email)) return null;
    normalized.add(email);
  }

  return normalized.size > 0 ? normalized : null;
}

/** Pure, fail-closed server configuration parser. */
export function getAdminAuthConfiguration(
  environment: AdminAuthEnvironment,
): AdminAuthConfiguration {
  const teamDomain = normalizeTeamDomain(environment.CLOUDFLARE_ACCESS_TEAM_DOMAIN);
  if (!teamDomain) return { enabled: false, reason: "team-domain" };

  const audience = normalizeAudience(environment.CLOUDFLARE_ACCESS_AUD);
  if (!audience) return { enabled: false, reason: "audience" };

  const allowedEmails = normalizeAllowlist(environment.ADMIN_ALLOWED_EMAILS);
  if (!allowedEmails) return { enabled: false, reason: "allowlist" };

  return { enabled: true, teamDomain, audience, allowedEmails };
}
