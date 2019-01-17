# gcp-oidc-proxy

Google Cloud Function for proxying requests to OIDC-authenticated endpoints.
For example, this can be used to make authenticated requests to resources
protected by a GCP Identity Aware Proxy (IAP).

## Deployment

```sh
$ gcloud functions deploy gcp-oidc-proxy \
    --runtime python37 \
    --entry-point handle_request \
    --trigger-http
```

- The service account for the Cloud Function needs the "Service Account Actor
  IAM" role.
- A `CLIENT_ID` environment variable needs to be set containing the OAuth2
  client ID, e.g. the client ID used by IAP.
- The service account for the Cloud Function needs to be added as a member of
  the protected resource with appropriate roles configured.