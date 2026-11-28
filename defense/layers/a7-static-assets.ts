/**
 * Browser delivery, L1: admission of the protected build's immutable static assets, composed AROUND the accepted shape gate, which stays
 * byte-identical (its route table is a pinned Slice-1/2 fact).
 *
 * The assets are an exact, closed list of GET targets fixed at construction: never a prefix, pattern or wildcard. Each entry is a plain
 * `/_next/static/...` path with no query, no `.`/`..` segment and no encoded or reserved character, short enough to stay a canonical
 * semantic target. A request whose target is EXACTLY one of them differs from a page only in its path, so every other L1 rule (method,
 * header count/bytes/alphabet, Host, framing) is the shape gate's own verdict for the same request addressed to "/", a GET-only page
 * that takes no query. Every other request, including an asset path with any query, is judged by the shape gate unchanged.
 *
 * The composite keeps the shape gate's layer id, as the semantic gate does. Absent (an empty list), the plane composes the shape gate alone.
 */
import type { Layer, LayerRequest, LayerVerdict } from "../core/types";

export const MAX_STATIC_ASSETS = 512;
const STATIC_ASSET_TARGET = /^\/_next\/static\/[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}){0,3}$/;
/** The declared GET-only, query-free page whose shape rules an exact asset request is judged by. */
const SHAPE_PROBE_TARGET = "/";

export function validateStaticAssets(assets: readonly string[]): ReadonlySet<string> {
  if (!Array.isArray(assets) || assets.length > MAX_STATIC_ASSETS) throw new Error(`static assets must be a list of at most ${MAX_STATIC_ASSETS} targets`);
  const set = new Set<string>();
  for (const target of assets) {
    if (typeof target !== "string" || target.length > 256 || !STATIC_ASSET_TARGET.test(target) || target.split("/").some((segment) => segment === "." || segment === "..")) {
      throw new Error("a static asset must be an exact /_next/static/ path");
    }
    if (set.has(target)) throw new Error("a static asset is listed twice");
    set.add(target);
  }
  return set;
}

export class StaticAssetGate implements Layer {
  readonly id = "a7.shape-gate" as const;
  private readonly assets: ReadonlySet<string>;

  constructor(private readonly shape: Layer, assets: readonly string[]) {
    this.assets = validateStaticAssets(assets);
    if (this.assets.size === 0) throw new Error("a static asset gate needs at least one asset");
  }

  evaluate(request: LayerRequest): LayerVerdict | Promise<LayerVerdict> {
    if (!this.assets.has(request.target)) return this.shape.evaluate(request);
    return this.shape.evaluate({ ...request, target: SHAPE_PROBE_TARGET });
  }
}
