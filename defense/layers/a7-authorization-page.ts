import { AUTHORIZATION_PAGE_TARGET, type Layer, type LayerRequest, type LayerVerdict } from "../core/types";

/** Apply the pinned query-free document shape to the one exact extra target. */
export class AuthorizationPageGate implements Layer {
  readonly id = "a7.shape-gate" as const;

  constructor(private readonly shape: Layer) {}

  evaluate(request: LayerRequest): LayerVerdict | Promise<LayerVerdict> {
    return this.shape.evaluate(request.target === AUTHORIZATION_PAGE_TARGET ? { ...request, target: "/" } : request);
  }
}
