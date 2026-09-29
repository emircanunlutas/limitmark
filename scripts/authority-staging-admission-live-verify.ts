// Gate 4B live never-initialized verifier -- RETIRED. The staging authority was
// intentionally initialized at Gate 7, so a never-initialized proof can no
// longer pass, and the transport it used (`wrangler dev` with a `remote: true`
// binding) can register a workers.dev subdomain and upload a temporary preview
// Worker before any state check runs (Gate 8 Phase 1A correction). The entry
// point and its npm script are kept only so that invoking them fails closed:
// this file has no import, reads no argument, environment variable, file or
// credential, spawns nothing, opens no socket, writes nothing to stdout,
// prints one fixed stderr line and exits 2. The harness Worker, its local
// Wrangler config and the lifecycle-private-contract validators remain as
// contract/test material only. A future live read needs its own reviewed
// transport; do not restore this one.

process.stderr.write("REFUSED: the Gate 4B staging admission live-verify entry point is RETIRED. The staging authority is initialized, and the Wrangler preview transport it used can register a workers.dev subdomain and upload a temporary preview Worker. No provider was contacted, nothing was spawned, and this is not a health check.\n");
process.exitCode = 2;
