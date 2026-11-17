#!/usr/bin/env bash
# Build the reusable ARM64 Android library and C header directly from this crate.
set -euo pipefail
core="$(cd "$(dirname "$0")/.." && pwd)"
ndk="${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to your installed side-by-side NDK}"
out="${1:-$core/target/android}"
toolchain="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$core/target}"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$toolchain/aarch64-linux-android26-clang"
export CC_aarch64_linux_android="$toolchain/aarch64-linux-android26-clang"
export AR_aarch64_linux_android="$toolchain/llvm-ar"
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C link-arg=-Wl,-z,max-page-size=16384"
cargo build --locked --release --lib --no-default-features --manifest-path "$core/Cargo.toml" --target aarch64-linux-android
mkdir -p "$out/arm64-v8a" "$out/include"
cp "$CARGO_TARGET_DIR/aarch64-linux-android/release/libcovert.so" "$out/arm64-v8a/"
cp "$core/include/covert.h" "$out/include/"
