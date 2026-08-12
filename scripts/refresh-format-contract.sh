#!/usr/bin/env bash
# Regenerates the committed archive-format capability contract consumed by
# downstream projects (zmanager-desktop manifest generation, zmanager-mobile
# snapshots). Run after any change to FORMAT_CAPABILITIES or the extension
# constants in zmanager-core, and commit the refreshed JSON.
#
# The byte-compare test in crates/zmanager-cli/tests/help_cli.rs fails CI when
# this file drifts from `zm formats --contract`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cargo run -q --manifest-path "$ROOT/crates/zmanager-cli/Cargo.toml" --bin zm -- formats --contract \
    > "$ROOT/crates/zmanager-cli/contracts/archive-formats.json"

echo "Refreshed crates/zmanager-cli/contracts/archive-formats.json ($(wc -c < "$ROOT/crates/zmanager-cli/contracts/archive-formats.json") bytes)"
