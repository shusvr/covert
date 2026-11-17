#!/usr/bin/env bash
set -euo pipefail
core="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$core/target}"
cargo build --locked --release --lib --no-default-features --manifest-path "$core/Cargo.toml"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
for test in ffi_smoke endpoint_ffi config_ffi; do
    "${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -I"$core/include" "$core/tests/$test.c" \
        -L"$CARGO_TARGET_DIR/release" -lcovert -Wl,-rpath,"$CARGO_TARGET_DIR/release" -o "$work/$test"
    "$work/$test"
done
