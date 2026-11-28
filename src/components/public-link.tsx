import Link from "next/link";
import type { ComponentPropsWithoutRef } from "react";

type Props = ComponentPropsWithoutRef<"a"> & { href: string };

export function PublicLink(props: Props) {
  // The read-only defense chain serves documents and build assets. Native links
  // avoid the App Router's background prefetches and click-time RSC requests.
  if (process.env.NEXT_PUBLIC_LIMITMARK_DOCUMENT_LINKS === "1") return <a {...props} />;
  return <Link {...props} />;
}
