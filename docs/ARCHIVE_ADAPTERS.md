# Adding an archive format

`zmanager-core` owns archive recognition, adapter selection, extraction safety,
and capability reporting. A new format must enter through the engine registry;
CLI, desktop, FFI, and mobile callers must not grow format-specific dispatch.

## Implementation checklist

1. Add one canonical `ArchiveFormatKind` and one `FormatCapabilities` row in
   `crates/zmanager-core/src/archive_format.rs`.
2. Add a stable `FormatId` in `crates/zmanager-core/src/engine/format.rs` and
   a static `AdapterDescriptor` for every read or create implementation.
3. Implement the smallest truthful adapter surface. Claim only operations and
   source access that the implementation supports:
   `List`, `Test`, `Extract`, `SelectedExtract`, `CopyToWriter`, and `Create`.
4. Register the adapter in the default `ArchivePlugin` in
   `crates/zmanager-core/src/engine/mod.rs`. Platform availability belongs in
   registration and capability status, not in consumer-side format matches.
5. Route nested/container formats through existing native adapters where
   possible. Keep extraction safety, atomic output, resource budgets, and
   cancellation in the shared engine pipeline.
6. Add fixture-backed tests for valid, corrupt, password, unsupported, and I/O
   failures. Add the format to `crates/zmanager-core/tests/engine_conformance.rs`
   for every operation it claims.
7. Add CLI compatibility coverage when an external creator or oracle exists.
   External tools are test inputs only; they must not become runtime or link
   dependencies of a supported artifact.
8. Verify the FFI `listFormats()` row is derived from the registry snapshot and
   that unknown input remains unsupported.

## Adapter template

```rust
static EXAMPLE_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "example-read",
    format: FormatId::EXAMPLE,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

struct ExampleAdapter;

impl ReadAdapterFactory for ExampleAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &EXAMPLE_DESCRIPTOR
    }

    // Implement only the operations claimed by EXAMPLE_DESCRIPTOR.
    // Return typed ArchiveError values; never probe a second adapter after an
    // adapter has claimed the format.
}
```

Creation uses `CreateAdapterFactory` and a separate descriptor with the
`Create` operation. The registry rejects duplicate `(FormatId, operation)`
claims, so an implementation cannot silently shadow another adapter.

## Required verification

From the repository root:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets
cargo check --workspace --all-targets
cargo test --workspace
cargo test -p zmanager-core --test hostile_archives
bash scripts/verify-artifact-profiles.sh
```

Review the resulting `capability_snapshot()` and `listFormats()` output. The
reported operations must exactly match the registered adapter descriptors, and
all consumer routes must continue to call the engine/browser/FFI interfaces.
