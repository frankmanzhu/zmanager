# zmanager-wim

Read-only parsing and decompression for Microsoft Windows Imaging (`.wim`)
files and split WIM sets (`.swm`).

The library supports stored resources, XPRESS-Huffman resources, and the WIM
dialect of LZX. It supports multiple images, split sets, metadata directory
trees, NTFS reparse-point targets, and resource SHA-1 verification.

LZMS is deliberately out of scope. This crate does not support solid WIM
resources or `.esd` distribution images; callers should report those as
unsupported rather than attempting to decode them as ordinary WIM resources.

The public API is format-oriented:

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
