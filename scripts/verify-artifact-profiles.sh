#!/usr/bin/env bash
# Verify that reduced artifact profiles do not accidentally retain libarchive.

set -euo pipefail

for package in zmanager-core zmanager-cli zmanager-ffi; do
    graph=$(cargo tree -e normal -p "$package" --no-default-features)
    if grep -Eq 'zmanager-libarchive(-sys)?([ v]|$)' <<<"$graph"; then
        echo "$package no-default-features profile still contains libarchive" >&2
        exit 1
    fi
done

cargo check -p zmanager-core --no-default-features --all-targets
cargo check -p zmanager-cli --no-default-features --all-targets
cargo check -p zmanager-ffi --no-default-features --all-targets
