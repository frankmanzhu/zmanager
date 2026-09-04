# TZAP product profiles

ZManager has one archive and identity contract, composed into product profiles
with positive Cargo features.

| Profile | Archive engine | Offline identity/catalog/sign/verify | Hosted login/enrollment/status | HTTP client |
|---|---|---|---|---|
| default | enabled | enabled | enabled | enabled in the CLI |
| `--no-default-features` | enabled | enabled | unavailable at product boundaries | absent from the CLI graph |

The feature name is `tzap-online` in `zmanager-cli` and `zmanager-ffi`. Hosted
transport is supplied by the explicit `zmanager-tzap-hosted` product crate. The
core's typed identity and transport contracts remain
available in reduced builds so local catalog, certificate parsing, document
signing, document verification, and offline `.tzap` inspection do not require
hosted account behavior. Network transport is supplied by the full CLI
profile; the FFI bridge keeps its UniFFI/JSON function set unchanged and
returns a structured unavailable result only for hosted auth launch, callback,
status, forget, and account-URL operations in reduced builds.
The hosted transport policy and validation boundary are described in
[`TZAP_HOSTED_TRANSPORT.md`](TZAP_HOSTED_TRANSPORT.md).

The reduced FFI profile keeps these operations real:

- bounded public `.tzap` metadata and X.509 inspection;
- local identity/catalog and certificate-inventory operations;
- offline document signing and verification;
- contact and recipient-key operations;
- the common archive engine/session contract.

The profile gate is checked by:

```sh
cargo check --workspace --no-default-features --all-targets
cargo test -p zmanager-core --no-default-features --lib
cargo test -p zmanager-ffi --no-default-features
bash scripts/verify-artifact-profiles.sh
```

Native consumer builds select the same profile through `ZMANAGER_TZAP_PROFILE`.
The root iOS script accepts `full` or `offline` (default `full`); the mobile
Android and pinned iOS wrappers default to `offline`. The desktop macOS
inspection-extension build also defaults to `offline`, while the desktop main
application keeps the explicit `tzap-online` feature as its default because
its account UI uses hosted authentication.

Adding a hosted operation requires an explicit `tzap-online` product-boundary
decision. It must not be added to archive-engine selection or to the stable
FFI type contract.

## `zmanager-cli` command split

The CLI dependency profile mirrors the same boundary, at the command level
rather than the module level:

| Build | `zmanager-tzap-hosted` | reqwest | Commands |
|---|---|---|---|
| default | present, without `reqwest-transport` | absent | `zm tzap …` |
| `tzap-online` | present, with `reqwest-transport` | present | `zm tzap …` + `zm auth …` |

`zmanager-tzap-hosted` is always a CLI dependency — it separates its own HTTP
transport behind `reqwest-transport` — so the default build keeps `zm tzap
sign`, `verify`, `contact`, `share`, and `certs` (which reads the local
identity catalogue) working entirely offline, while dropping reqwest and the
hosted commands under `zm auth` (`login`, `callback`, `status`, `forget`,
`account`, `me`, `cert enroll|renew|revoke`, `device retire|revoke`)
entirely. See
[`cli-command-structure-and-profiles-plan.md`](../implementation-docs/cli-command-structure-and-profiles-plan.md)
for the full command tree and rationale.
