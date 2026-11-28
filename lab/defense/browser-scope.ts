/**
 * The declared read-only browser scope of the built application behind the defense chain.
 *
 * Pages: exactly the GET page targets the browser L1 and L2 composition admit, including one opt-in authorization document.
 * Assets: exactly the files of the build's own immutable `.next/static` output, read from disk, as `/_next/static/...` targets. The list
 * is closed (no prefix or pattern), bounded, and every file must fit the relays' response bound, otherwise it fails closed at startup
 * instead of being cut off at runtime. The harness gives this list to the Defense Plane; the application wrapper derives it again from
 * its own build directory, so neither side serves or admits anything the build does not contain.
 */
import { readdirSync, statSync } from "node:fs";
import path from "node:path";
import { AUTHORIZATION_PAGE_TARGET } from "../../defense/core/types";
import { FORM_ROUTE_TARGETS } from "../../defense/core/enrollment";
import { validateStaticAssets } from "../../defense/layers/a7-static-assets";

export const READ_ONLY_PAGE_TARGETS: readonly string[] = Object.freeze(["/", "/gizlilik", "/test-talep-et/tesekkurler", ...FORM_ROUTE_TARGETS, AUTHORIZATION_PAGE_TARGET]);

/** Equals the plane's and the boundary's relayed response bound (pinned by a test). */
export const MAX_RELAYED_ASSET_BYTES = 1_048_576;

export function staticAssetTargets(buildRoot: string): string[] {
  const targets: string[] = [];
  const walk = (directory: string, relative: readonly string[]): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const segments = [...relative, entry.name];
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(full, segments);
      else if (entry.isFile()) {
        if (statSync(full).size > MAX_RELAYED_ASSET_BYTES) throw new Error(`static asset exceeds the relayed response bound: ${segments.join("/")}`);
        targets.push(`/_next/static/${segments.join("/")}`);
      } else throw new Error(`unexpected static entry: ${segments.join("/")}`);
    }
  };
  walk(path.join(buildRoot, ".next", "static"), []);
  targets.sort();
  if (targets.length === 0) throw new Error("the build has no static assets");
  validateStaticAssets(targets);
  return targets;
}
