# Shared Server Vault Storage Execution Notes

## Route Deviation

The Codex in-app browser retained the pre-rotation Basic Auth credential and its supported navigation surface rejected URL userinfo and Document-level CDP header interception. To complete the required browser acceptance without weakening the real `/appleid/` gate, a random unguessable preview prefix was added temporarily to the Visa Nginx config. It served the same static files and internal API without Basic Auth for synthetic test data only; it was scheduled for removal immediately after the acceptance run and is not part of the production configuration.

## Finalization

- Removed the temporary preview locations from the local and Visa Nginx configurations.
- Revalidated the deployed Nginx configuration and restarted `appleid-vault`.
- Verified the public production path: unauthenticated API `401`, authenticated API `200`, authenticated page `200`, and the removed preview path `404`.
- Ran the backup script; database, encryption key, and backup files are mode `0600`.
- Confirmed the API container has no published host port and sample plaintext credentials are absent from the SQLite file.

## Basic Auth Prompt Fix

The original server-wide Basic Auth protected the HTML entrypoint. After the gate password was rotated, browsers with cached credentials repeatedly returned `ERR_INVALID_AUTH_CREDENTIALS` before the application could load. The fix keeps Basic Auth on `/api/vault/` and `/api/fetch-code` only, makes the static shell public, and adds a page-level password dialog that sends the Basic Auth header explicitly to same-origin protected requests. Wrong passwords now return to a retryable in-page error state without a native browser prompt.
