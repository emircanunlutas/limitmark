# Cloud Run laboratory invocation boundary

The laboratory service uses `ingress: all` only so the Cloudflare Worker can
reach its `run.app` hostname. Requests still require Cloud Run IAM and the
application gates.

The eventual Cloudflare invocation identity must have:

```text
roles/run.invoker
```

on `limitmark-public-inquiry-lab` only. Do not grant `allUsers`, `allAuthenticatedUsers`,
or a project-wide invoker role. The ID-token audience must be exactly:

```text
https://<LAB_ORIGIN_HOSTNAME>
```

and the Worker must send it in `X-Serverless-Authorization: Bearer <ID_TOKEN>`.
The application separately validates the signed laboratory ingress envelope,
public/origin host split, origin secret, PRE/POST admission, Turnstile, and
laboratory database configuration.

Cloudflare Workers do not provide a built-in Google service-account ID-token
source in this repository. No service-account key or static token is included.
Before deployment, implement and independently review a keyless federation
path (or stop the laboratory deployment); the lab signer fails closed while
that token provider is absent.
