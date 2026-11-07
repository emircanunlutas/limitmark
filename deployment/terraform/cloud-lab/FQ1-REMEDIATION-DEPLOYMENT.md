# FQ1 remediation - deployment preparation (prepared 2026-11-07; NOTHING in this file has been executed)

Status: the application patch and Terraform change are implemented and locally tested. **Do not build or deploy until the owner explicitly authorizes it.**

## 1. What changes
Application (image rebuild required; `Dockerfile` itself is unchanged):
- `src/lib/public-origin.ts` - `resolveOriginProtectionEnvironment`: for the explicit `LIMITMARK_RUNTIME=cloud-run-lab` only, the origin gate reads `LAB_PUBLIC_ORIGIN_SECRET`, `LAB_ORIGIN_HOSTNAME`, `LAB_PUBLIC_HOSTNAME`; raw `PUBLIC_ORIGIN_*` are ignored; a missing value is `undefined` and is rejected. Other runtimes: the same object, unchanged.
- `src/proxy.ts` - evaluates the gate on the resolved environment.
- `src/lib/public-inquiry-runtime.server.ts` - the existing validation is extracted unchanged into `isLaboratoryRuntimeConfigurationValid` (a type predicate used by the API runtime and the page) and `getLaboratoryIntakeState` (closed unless valid; Turnstile site key from `LAB_TURNSTILE_SITE_KEY`). `PUBLIC_ORIGIN_SECRET` stays in `forbiddenProductionKeys`.
- `src/app/test-talep-et/page.tsx` - `process.env.LIMITMARK_RUNTIME === "cloud-run-lab" ? getLaboratoryIntakeState : getPublicIntakeState` (production decision untouched).
- `src/lib/public-inquiry-handler.server.ts` - the browser `Origin` must equal `https://<PUBLIC_ORIGIN_PUBLIC_HOSTNAME>` (laboratory; derived from server configuration) / `https://limitmark.com` (production, unchanged); the request URL host check against the internal Cloud Run hostname is unchanged.
- `tests/lab-fq1-remediation.test.ts` - new regression tests.

Infrastructure: `cloud-run.tf` - remove the three `PUBLIC_ORIGIN_*` env entries added in commit 1fe408d; the image digest variable changes to the rebuilt image.

## 2. Coupling rule (must hold)
| Image | `PUBLIC_ORIGIN_*` env | Result |
| --- | --- | --- |
| old (`sha256:cad6a3e6...`) | present (current rev `-00002-mrd`) | pages/assets 200; submission runtime disabled (503); form page closed |
| old | removed | every page/asset 404 (the original defect) |
| new | present | runtime disabled, form closed, submissions 503 |
| **new** | **removed** | **intended** |

Therefore the image and the env removal MUST ship in one Terraform apply (one new Cloud Run revision). Never apply the env removal alone and never roll the image without the Terraform change.

## 3. Deployment sequence (each step needs the owner's authorization)
1. Commit the patch locally (done only after review); build from that clean commit: `docker build --platform linux/amd64 -t europe-west3-docker.pkg.dev/limitmark-field-qual/limitmark/limitmark-app:build-<sha> .`, push, record the digest.
2. Set `cloud_run_image` in the git-ignored `terraform.tfvars` to the new `@sha256:` digest.
3. `terraform fmt -check`, `terraform validate`, `terraform plan -out=lab.tfplan`; require exactly **0 to add, 1 to change, 0 to destroy**, the only diff being `image` (old digest -> new digest) and the removal of the three env entries, with no IAM, network, scaling or other env change.
4. `terraform apply lab.tfplan` (the exact saved plan).
5. Verify: new revision Ready and 100 % traffic; unauthenticated `run.app` = 403; `https://lab.limitmark.com/` and static assets 200; `/test-talep-et` renders the form and the Turnstile widget; a wrong-origin POST gets the generic 503; collector started; app independent of collector.
6. Only then rerun the FQ1 browser matrix.

## 4. Rollback to the currently deployed revision
Currently deployed: `limitmark-public-inquiry-lab-00002-mrd` (old image `sha256:cad6a3e69df946d0fba74d24bee696b7c635009bd3f1b695729dd1a23baffaee` with the three `PUBLIC_ORIGIN_*` vars). Cloud Run keeps it.
1. Immediate (seconds, no Terraform): `gcloud run services update-traffic limitmark-public-inquiry-lab --region europe-west3 --project limitmark-field-qual --to-revisions limitmark-public-inquiry-lab-00002-mrd=100`.
2. Reconcile Terraform with reality afterwards (otherwise the next plan reverts the traffic split): restore the previous `cloud_run_image` digest in `terraform.tfvars`, `git revert` the env-removal change (restores the three entries), then plan (expect 0/1/0 or 0/0/0) and apply.
3. Public ingress can be cut at any time by detaching the signer custom domain (`wrangler` removal of `lab.limitmark.com`) or removing the service-scoped `run.invoker` binding; neither is needed for a rollback.

## 5. Residual risks
- The new image has been tested only locally (unit and regression level); the first live proof is step 5 above.
- The Origin gate for the laboratory is compared with a configured value; `x-forwarded-host` and `Host` are still checked by the origin gate, not used as trust anchors for `Origin`.
- Telemetry export to Cloud Monitoring remains unverified until submissions run.
