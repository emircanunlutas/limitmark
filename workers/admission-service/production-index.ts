// Production admission Worker entry. Exports ONLY the production-pinned classes: no laboratory and no staging Durable Object class, entrypoint or
// authority id is exported (hence bindable by name) from a Worker built from this module. The implementation stays in ./index (shared with the staging and
// laboratory entries, which keep their own entry modules); this file only narrows what the production bundle exposes.
export { ProductionAdmissionAuthority, AuthorityLifecycleOnly, AuthorityLifecycleReadOnly, AdmissionServiceWorker } from "./index";
export { AdmissionServiceWorker as default } from "./index";
