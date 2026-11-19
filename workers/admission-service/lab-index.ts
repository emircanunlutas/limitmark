// Lab admission Worker entry (third environment). Exports ONLY lab-pinned classes: no Production or staging Durable Object class,
// entrypoint or authority id is reachable from a Worker built from this module.
export { LabAdmissionAuthority, LabAuthorityLifecycleOnly, LabAuthorityLifecycleReadOnly, LabAdmissionServiceWorker } from "./index";
export { LabAdmissionServiceWorker as default } from "./index";
