# Hosted TZAP transport boundary

Hosted TZAP behavior is owned by the reusable `zmanager-core` auth modules;
CLI, desktop, and FFI layers only provide product adapters. The boundary is
typed by `TzapAuthHttpRequest`, `TzapAuthHttpResponse`, and
`TzapAuthHttpTransport`, so UI/FFI DTOs and provider-specific secrets do not
cross into the core client.

Each request carries `TzapAuthRequestOptions`:

- connect and total request timeouts are explicit and default to 10 and 30
  seconds;
- retries are bounded to three attempts, use a 50 ms backoff, and apply only
  to idempotent `GET` requests returning `429` or `5xx` (or a transport
  failure); hosted `POST` operations are not replayed;
- `TzapAuthCancellation` provides cooperative cancellation before and after a
  transport call, and adapters pass it through to their HTTP implementation.

The core validates OAuth state, redirect URI, PKCE, session audience, provider
material, current-user fields, enrollment certificate chains, status freshness,
and CRL contents before any session or identity inventory update. Bearer
tokens and private key material use redacting, zeroizing secret wrappers.

The full CLI adapter maps these options to its `reqwest` client. Reduced
profiles keep the typed contract and local/offline operations but omit hosted
HTTP dependencies. Build selection is documented in
[`TZAP_PROFILES.md`](TZAP_PROFILES.md).

Focused verification:

```sh
cargo test -p zmanager-core auth_client
cargo test -p zmanager-core --test tzap_obligation_harness
cargo test -p zmanager-ffi --no-default-features
```
