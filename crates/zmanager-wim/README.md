# zmanager-wim

Read-only parsing and decompression for Microsoft Windows Imaging (`.wim`)
files and split WIM sets (`.swm`).

The library supports stored resources, XPRESS-Huffman resources, and the WIM
dialect of LZX. It supports multiple images, split sets, metadata directory
trees, NTFS reparse-point targets, and resource SHA-1 verification. Multiple
images are exposed under `imageN/` prefixes so entries from different images
cannot collide.

The public API is read-oriented:

- `WimArchive::open` opens a WIM and discovers sibling parts of a split set.
- `WimArchive::entries` lists normalized files, directories, and reparse-point
  entries.
- `WimArchive::read_entry_data` decodes one file or stream into memory.
- `WimArchive::verify` checks every regular-file resource's size and SHA-1.
- `list` provides a one-shot listing convenience function.

Filesystem extraction policy is intentionally not part of this crate; callers
that need safe extraction should apply their own policy or use
`zmanager-core`.

LZMS is deliberately out of scope. This crate does not support solid WIM
resources or `.esd` distribution images; callers should report those as
unsupported rather than attempting to decode them as ordinary WIM resources.

```rust
use zmanager_wim::WimArchive;

let mut archive = WimArchive::open("install.wim")?;
let entries = archive.entries()?;
for entry in entries {
    println!("{}", entry.path);
}
# Ok::<(), zmanager_wim::WimError>(())
```

## License

The WIM parser is licensed under Apache-2.0. The private WIM-LZX decoder is
derived from `lzxd` 0.2.7 by Lonami and retains its MIT/Apache-2.0
attribution; see `src/lzx` and `vendor/`.
