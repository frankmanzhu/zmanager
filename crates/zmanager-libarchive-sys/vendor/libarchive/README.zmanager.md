# ZManager libarchive Vendor Note

This directory vendors the upstream libarchive 3.8.9 release source.

- Upstream: https://github.com/libarchive/libarchive
- Release: v3.8.9
- Source archive: `libarchive-3.8.9.tar.xz`
- SHA-256: `528f9c91e11238cbb5ce6d79b20fa3bb48a5cd124008036af1913d84fc5ba420`

ZManager builds this source through `crates/zmanager-libarchive-sys`.
Do not edit files under `libarchive-3.8.9/` directly. If a local change becomes
unavoidable, keep it as a documented patch outside the upstream source tree and
explain the affected platform and replacement path here.

## Bumping libarchive

1. Replace the `libarchive-<version>/` directory with the new release source
   (and update this note's version, SHA-256, and source archive).
2. Commit and push. The version is discovered by glob everywhere — `build.rs`
   and both bindgen scripts pick up whatever single `libarchive-*` directory
   is vendored.
3. The "Regenerate libarchive bindings" workflow runs automatically on the
   push (paths: `vendor/libarchive/**` and `build.rs`), regenerates both
   checked-in binding files, and auto-commits them. Review that commit's diff
   against the new API surface. (workflow_dispatch can be used for a
   one-off regeneration of a single target.)
