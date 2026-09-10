import "server-only";

const email = process.env.CONTACT_EMAIL?.trim();

export const siteConfig = {
  name: "Resilience Testing",
  // A plain mailbox only: never allow arbitrary schemes or query parameters.
  contactEmail: email && /^[^\s@?&#]+@[^\s@?&#]+\.[^\s@?&#]+$/.test(email) ? email : null,
};
