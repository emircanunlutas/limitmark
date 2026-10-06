/**
 * Slice 3 production plane entry. L2 is always present: there is no flag, mode or message that removes it, and this entry passes NO
 * injected dependency to the runtime, so its module graph contains no fault wrapper, no verdict-override implementation and no collapse
 * handler. The legacy Slice-1/2 composition is `main.ts` (unchanged); this is the composition that has L2.
 *
 * Control channel (parent -> plane): init | ack | fin | stop. There is no network control surface, and nothing in an HTTP request can arm
 * or change anything.
 */
import { startPlane } from "./runtime";

startPlane();
