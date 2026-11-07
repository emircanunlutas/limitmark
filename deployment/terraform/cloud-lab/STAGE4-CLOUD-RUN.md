# Stage 4 - Cloud Run (prepared 2026-11-07; NOT applied)

Three things are validated **independently**, in this order. A pass on one proves nothing about the next.

| # | What | Proof | Needs Cloudflare? |
| --- | --- | --- | --- |
| 1 | Cloud Run infrastructure: revision Ready, IAM-only invocation, VPC attached, sidecar up | `gcloud run revisions describe`; an unauthenticated request is refused (403); an IAM-authenticated POST with no ingress header returns the *ingress* rejection (4xx), **not** the generic 503 | no |
| 2 | Application to PostgreSQL over strict TLS from the Cloud Run network | a one-off Cloud Run **job** from the same image, service account and VPC (a new resource: needs approval), or the first real submission | no (job) / yes (real submission) |
| 3 | Public traffic: Cloudflare signer, Turnstile, admission Worker, `run.app` origin | end-to-end submission through the public hostname | yes |

Fail-closed behaviour observed with the real image (do not weaken it to satisfy a probe): with no lab runtime the route answers 404; with
`LIMITMARK_RUNTIME=cloud-run-lab` and incomplete configuration it answers 503 with the generic "unavailable" state; the process still starts, so the
default TCP startup probe on 8080 passes. The probe therefore proves only that the process is up. Configuration validity is proven by check 1 (a 4xx
ingress rejection instead of 503) and database reachability by check 2. No health route is added.

The application's own database client options (pinned CA, `rejectUnauthorized: true`, server name = URL host) were exercised locally against a TLS
PostgreSQL whose certificate has only an IP SAN: the pinned CA connects; a wrong CA and a host outside the SAN are both rejected.

## Images (immutable, digest-pinned, Artifact Registry only)

`cloud_run_image` and `otel_collector_image` are validated to be `...-docker.pkg.dev/<project>/limitmark/<name>@sha256:<64 hex>`. Cloud Run is not
given the mutable Docker Hub collector tag.

```powershell
gcloud auth configure-docker europe-west3-docker.pkg.dev        # credential helper; no key file
docker build --platform linux/amd64 -t europe-west3-docker.pkg.dev/limitmark-field-qual/limitmark/limitmark-app:build-<sha> .
docker push europe-west3-docker.pkg.dev/limitmark-field-qual/limitmark/limitmark-app:build-<sha>
gcloud artifacts docker images describe europe-west3-docker.pkg.dev/limitmark-field-qual/limitmark/limitmark-app:build-<sha> --format="value(image_summary.digest)"
# Collector: copy the multi-arch index without changing its digest (a plain pull/tag/push would change it)
docker buildx imagetools create -t europe-west3-docker.pkg.dev/limitmark-field-qual/limitmark/otelcol-contrib:0.136.0 otel/opentelemetry-collector-contrib:0.136.0
gcloud artifacts docker images describe europe-west3-docker.pkg.dev/limitmark-field-qual/limitmark/otelcol-contrib:0.136.0 --format="value(image_summary.digest)"
```

The image built from this commit succeeded locally: about 1.1 GB, runs as `node`, contains no `src`, `.env` or secrets, and Next is ready in about
150 ms. The size is a cold-start cost rather than a blocker; a standalone-output build would shrink it and is deliberately out of scope.

## Secrets: nine versions are still missing (the two database secrets exist)

Cloud Run resolves `latest` when an instance starts, so a missing version fails the revision. Values are generated and written straight to Secret
Manager (`--data-file=-` or a transient `0600` file), never printed and never placed in Terraform.

| Secret | Format | Source | Shared with |
| --- | --- | --- | --- |
| `limitmark-lab-public-origin-secret` | base64url, 32 random bytes (43 chars) | generate locally | signer Worker `LAB_PUBLIC_ORIGIN_SECRET` (identical) |
| `limitmark-lab-ingress-request-binding-key` | base64url, 32 random bytes | generate locally | app only |
| `limitmark-lab-admission-release-rpc-key` | base64url, 32 random bytes | generate locally | admission Worker `ADMISSION_CURRENT_RPC_KEY` |
| `limitmark-lab-admission-release-key-id` | `[A-Za-z0-9_-]{1,64}` | choose | admission Worker `ADMISSION_CURRENT_KEY_ID` |
| `limitmark-lab-ingress-audience` | `[A-Za-z0-9_.:-]{1,128}` | choose | signer Worker `LAB_INGRESS_AUDIENCE` |
| `limitmark-lab-ingress-public-keys` | active signing-key rollout JSON (time-windowed) | public half of the signer key; `deployment/ingress-signing-key-rollout.template.json` | signer key id |
| `limitmark-lab-turnstile-site-key`, `-secret-key` | **real** Cloudflare Turnstile keys (the runtime rejects the test keys) | Cloudflare dashboard | public form |
| `limitmark-lab-otel-collector-config` | file `deployment/otel-collector.cloud-run-lab.yaml` | repository | collector sidecar |

Locally generable now: origin secret, request-binding key, RPC key, key id, audience, collector config. Blocked on Cloudflare: the Turnstile keys and
the signer key pair (and so the ingress public keys). The rollout has an activation window; it must be active both when an instance starts and when
the request arrives.

Fixed values for the Worker configuration: Cloud Run origin hostname `limitmark-public-inquiry-lab-1045646810362.europe-west3.run.app` (the ID-token
audience is `https://` plus that hostname); app service account `limitmark-lab-app@limitmark-field-qual.iam.gserviceaccount.com` with unique ID
`112648989669419541876` (admission Worker `GOOGLE_SERVICE_ACCOUNT_SUBJECT`).

The Cloudflare signer currently authenticates with a Google **service-account JSON key** for `limitmark-lab-invoker`
(`LAB_GOOGLE_SERVICE_ACCOUNT_CREDENTIALS`). That is a long-lived key and needs explicit approval and a rotation plan before it is created.

## Plan (whole module against the remote state, no `-target`): 7 add, 0 change, 0 destroy

`google_cloud_run_v2_service.lab`, `google_cloud_run_v2_service_iam_member.invoker`, `google_project_iam_member.app_metric_writer`,
`google_compute_subnetwork_iam_member.cloud_run_network_user`, and the project services `run`, `monitoring`, `logging`.

| New IAM binding | Scope | Why |
| --- | --- | --- |
| `roles/run.invoker` to `limitmark-lab-invoker` | this one service | the Cloudflare signer's ID token is the only way in; no `allUsers`, no project-wide invoker |
| `roles/monitoring.metricWriter` to `limitmark-lab-app` | project (the role cannot be narrower) | the collector sidecar writes the OTel metrics |
| `roles/compute.networkUser` to the Cloud Run service agent | `limitmark-lab-subnet` only | Direct VPC egress. Believed redundant for a same-project subnet (the agent's own role may suffice); kept because removing it risks a failed first deploy. Drop it after a successful deploy shows it is unneeded. The service agent must exist first: enable the Run API, then `gcloud beta services identity create --service=run.googleapis.com` |

Operational notes: the service uses request-based CPU, so the collector's periodic export can stall between requests and metrics may lag until the
next request; `cpu_idle=false` would fix that at instance-based cost and is a later decision. `PRIVATE_RANGES_ONLY` sends only private ranges into the
VPC, so the public admission Worker is reached directly and needs no NAT. The client `connect_timeout` is 5 s; the first request after a cold start also
pays the Direct VPC egress attach.

## Bootstrap edits and the PostgreSQL VM

`google_compute_instance.postgres` now ignores `metadata_startup_script`: changing it makes the provider **replace the VM**, which can change its private
IP (certificate SAN, database URL secret). The certificate-renewal timer was therefore installed in place on the live VM from the same rendered file, and
a rebuilt VM gets it from the bootstrap. To rebuild deliberately: `terraform apply -replace=google_compute_instance.postgres`, then re-export the CA.
