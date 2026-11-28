import { PublicLink } from "./public-link";
import type { ComponentProps } from "react";

type Props = ComponentProps<typeof PublicLink> & { variant?: "primary" | "secondary" | "text" };

export function ButtonLink({ variant = "primary", className = "", ...props }: Props) {
  return <PublicLink className={`${variant === "text" ? "text-link" : `button button-${variant}`} ${className}`.trim()} {...props} />;
}
