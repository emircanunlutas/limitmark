/**
 * The link-navigation mode of a build, read from what the reference browser did on the journey's link clicks.
 * Exactly three clicks are required and they must all be client navigations (default build) or all native documents
 * (document-link build). A mixed or incomplete trace is a harness or build fault and must never be read as either mode.
 */
export type LinkMode = "client" | "document";

export const REFERENCE_LINK_CLICKS = 3;

export function referenceLinkMode(navigations: readonly string[]): LinkMode {
  if (navigations.length !== REFERENCE_LINK_CLICKS) throw new Error(`expected exactly ${REFERENCE_LINK_CLICKS} reference link clicks, observed ${navigations.length}`);
  if (navigations.every((navigation) => navigation === "client")) return "client";
  if (navigations.every((navigation) => navigation === "document")) return "document";
  throw new Error(`reference link clicks are neither all client nor all document navigations: ${navigations.join(", ")}`);
}

/** The mode the build exhibits must agree with NEXT_PUBLIC_LIMITMARK_DOCUMENT_LINKS as seen by the harness. */
export function assertModeMatchesEnvironment(mode: LinkMode, environmentValue: string | undefined): void {
  const expected: LinkMode = environmentValue === "1" ? "document" : "client";
  if (mode !== expected) throw new Error(`NEXT_PUBLIC_LIMITMARK_DOCUMENT_LINKS does not match the build under test: the build navigates by ${mode}, the environment expects ${expected}`);
}