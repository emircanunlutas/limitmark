# Cloud Run laboratory invocation boundary

The laboratory service uses `ingress: all` only so the Cloudflare Worker can
reach its `run.app` hostname. Requests still require Cloud Run IAM and the
application gates.

The eventual Cloudflare invocation identity must have:

```text
roles/run.invoker
```

on `limitmark-public-inquiry-lab` only. Do not grant `allUsers`, `allAuthenticatedUsers`,
or a project-wide invoker role. The service account must have no permissions to
modify Cloud Run services, secrets, databases, or IAM. Do not reuse any
production service account. The ID-token audience must be exactly:

```text
https://<LAB_ORIGIN_HOSTNAME>
```

and the Worker must send it in `X-Serverless-Authorization: Bearer <ID_TOKEN>`.
The application separately validates the signed laboratory ingress envelope,
public/origin host split, origin secret, PRE/POST admission, Turnstile, and
laboratory database configuration.

Cloudflare Workers do not provide a built-in Google service-account ID-token
source in this repository. The laboratory signer uses a dedicated
`LAB_GOOGLE_SERVICE_ACCOUNT_CREDENTIALS` Worker secret containing the Google
service-account JSON. It creates short-lived RS256 JWT bearer assertions with
WebCrypto, exchanges them for an OAuth access token, and calls the Google IAM
Credentials `generateIdToken` API with the exact Cloud Run audience. The
resulting ID token is sent only in `X-Serverless-Authorization`.

The secret must be rotated explicitly by replacing the Worker secret and
redeploying the laboratory Worker. Missing or malformed credentials disable
the signer. No credentials, assertions, access tokens, or ID tokens are logged.
The secret is not represented as a plaintext Wrangler configuration value;
operators must bind it through the reviewed Worker-secret rotation procedure
using the exact name `LAB_GOOGLE_SERVICE_ACCOUNT_CREDENTIALS`.
