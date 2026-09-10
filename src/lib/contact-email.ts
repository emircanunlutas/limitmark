import { z } from "zod";

const mailbox = z.email().max(254).refine((value) => !/[?&#]/.test(value));

export function getContactEmail(value: string | undefined): string | null {
  const result = mailbox.safeParse(value?.trim());
  return result.success ? result.data : null;
}
