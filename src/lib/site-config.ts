import "server-only";
import { getContactEmail } from "./contact-email";

export const siteConfig = {
  name: "Resilience Testing",
  // A plain mailbox only: never allow arbitrary schemes or query parameters.
  contactEmail: getContactEmail(process.env.CONTACT_EMAIL),
};
