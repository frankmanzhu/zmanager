#!/usr/bin/env bash
# Verify that every supported artifact profile remains native-only.

set -euo pipefail

for package in zmanager-core zmanager-cli zmanager-ffi; do
    for profile in default no-default-features; do
        profile_args=()
        if [[ "$profile" == "no-default-features" ]]; then
            profile_args+=(--no-default-features)
        fi
        graph=$(cargo tree -e normal -p "$package" "${profile_args[@]}")
        forbidden='libarchive|bsdtar'
        if [[ "$profile" == "no-default-features" && "$package" == "zmanager-cli" ]]; then
            forbidden+='|reqwest'
        fi
        if grep -Eiq "$forbidden" <<<"$graph"; then
            echo "$package $profile still contains a forbidden hosted/backend runtime dependency" >&2
            exit 1
        fi
    done
done

cargo check -p zmanager-core --no-default-features --all-targets
cargo check -p zmanager-cli --no-default-features --all-targets
cargo check -p zmanager-ffi --no-default-features --all-targets
