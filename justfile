run config="ex1":
    cargo b && sudo ./target/debug/covert run ./examples/{{quote(config)}}.toml

# Build target/release/libcovert.so (Linux). C declarations: include/covert.h.
lib:
    cargo build --release --lib --no-default-features

# Build the ARM64 Android .so and header; ANDROID_NDK_HOME must name the NDK.
android:
    scripts/build-android.sh

# Build the host library and check its public C ABI.
test-ffi:
    scripts/test-ffi.sh
