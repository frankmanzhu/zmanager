# Windows Build Notes

Windows builds use the MSVC Rust targets. Archive readers and writers are
implemented by the native Rust adapters in this workspace; there is no bundled
compatibility archive runtime.

## Supported targets

| Platform | Rust target | vcpkg triplet | Runner |
| --- | --- | --- | --- |
| Windows x64 | `x86_64-pc-windows-msvc` | `x64-windows-static` | `windows-2025` |
| Windows ARM64 | `aarch64-pc-windows-msvc` | `arm64-windows-static` | `windows-11-arm` |

## Required tools

- Rust stable with the target being tested.
- Visual Studio C++ build tools for the target architecture.
- Windows SDK.
- CMake and vcpkg for the native compression and cryptography dependencies.

The checked-in Windows CI script installs the static vcpkg dependencies and
sets the MSVC environment before invoking Cargo:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\ci-windows.ps1 `
  -Target "x86_64-pc-windows-msvc" `
  -Triplet "x64-windows-static" `
  -VcArch "x64" `
  -VsComponent "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
```

Use `arm64-windows-static`, `arm64`, and the ARM64 Visual Studio component for
the ARM64 target. Add `-Package -OutDir dist` to create the release zip.

## Build behavior

The workspace uses native Rust format adapters and the dedicated bundled RAR
and Apple Archive implementations where those platforms support them. The
registry is the source of truth for available list, test, extract, and create
operations. Unsupported or platform-gated formats fail closed and are reported
through the same capability snapshot used by the CLI and FFI.

Static vcpkg triplets keep the compression and cryptography dependencies
inside the release executable. The Windows package should not require vcpkg
DLLs beside `zm.exe`; normal Windows system DLLs remain supplied by the OS.

## CI

The CI workflow covers macOS, Linux, and both supported Windows targets. The
Windows jobs call `scripts/ci-windows.ps1`, which initializes Visual Studio,
installs the target triplet, runs the workspace tests, and builds both the
full and offline release packages.
