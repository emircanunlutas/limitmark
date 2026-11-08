// Test-only entry: the production admin gateway module also exports non-handler values, which workerd rejects as module exports.
export { default } from "../../../workers/admin-gateway/index";
