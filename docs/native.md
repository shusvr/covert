# Native library and Android integration

This repository is the source of `libcovert.so` and `include/covert.h`.
The Android app has no Rust source copy or separate Rust manifest/lockfile.

Build the host C library:

```sh
cargo build --release --lib --no-default-features
```

Build the ARM64 Android library (Linux host, installed Android NDK and Rust target):

```sh
rustup target add aarch64-linux-android
export ANDROID_NDK_HOME=/path/to/Android/Sdk/ndk/30.0.16248370
just android
```

The SDK artifacts are `target/android/arm64-v8a/libcovert.so` and
`target/android/include/covert.h`. Android API 26 and 16 KiB page alignment are
used. CLI dependencies are optional and excluded by `--no-default-features`.
The default Cargo features continue to build the CLI normally.

In the Android project, set `COVERT_CORE_DIR` or Gradle's `covertCoreDir` property
to this checkout, then build the APK. Gradle tracks the core inputs, runs this
repository's build script, and packages the resulting library alongside
`libcovert_jni.so`. JNI links against the canonical header in this checkout and
checks `covert_abi_version()` against `COVERT_ABI_VERSION` on load.

The C ABI is version 2. In particular, the legacy `covert_tunnel_process` now
explicitly takes a `uint8_t flush_on_error` (0 or 1), matching the Rust API.
Consumers must rebuild against the matching header and library together.

## Rust errors

The Rust APIs share `covert::Error` and `covert::Result<T>`. Codec, crypto,
tunnel, transport and internal FFI work use the same error type. Underlying
I/O, IP parsing, crypto, layout parsing and external adapter errors retain their
sources through `std::error::Error::source()`; adapters can use
`covert::Error::adapter` to preserve errors from external libraries.

The C ABI continues returning its existing integer status codes. The FFI boundary
maps shared Rust errors into those codes and catches panics; this refactor does
not change the C ABI version or function signatures.

## Main configuration API

`CovertConfig` is an opaque pointer to `crate::config::Config` itself. There is no
second Rust client configuration or Android JSON model. `src/ffi/config.rs`
exposes its interface and peer fields:

- Create/free the handle; add, remove and count peers.
- Use `COVERT_CONFIG_INTERFACE` for interface fields, or a peer index for peer fields.
- Get/set Base64 keys, optional PSK, layout, addresses, allowed IP ranges, resolved
  endpoints, device/peer identity, MTU, transport, port, ICMP mode and liveness.
- Clear optional liveness values to restore interface/default inheritance.

Setters parse values before committing and leave the config unchanged on error.
Getter buffers are copies and follow the normal Rust buffer ownership rules.
`covert_config_validate` checks structural layout/MTU invariants. The host remains
responsible for its own platform policy (such as Android's MTU range and required
TUN addresses). Native endpoint creation requires exactly one peer and either UDP
or ICMP EchoReply. OnlyEcho remains representable in the main Config but is not
supported by the fixed-remote client adapter.

Android's `NativeConfig` owns this handle with `AutoCloseable`, serializes access,
and keeps it alive throughout the native polling loop. Java edits and reads the
core fields through JNI; the endpoint copies the resulting main Config. The
endpoint IP input, DNS servers and editable UI draft stay in Android. Endpoint
addresses must be numeric literals: Android parses them without DNS and writes
the numeric peer endpoint through the FFI before binding the protected socket to
the selected physical network. The encrypted profile
format is unchanged, so existing saved profiles still load.

## Client endpoint API

New native integrations create a main config with `covert_config_new`, add a peer
and set the interface/peer fields, then call `covert_endpoint_from_config`. The
endpoint uses the same `transport::Endpoint` as the CLI and owns a config clone;
the original config can be edited or freed afterward. The original
`covert_endpoint_client_new` convenience constructor remains available to C
consumers that only have keys/layout/liveness values.

The host owns the connected socket, selects VPN routes and supplies IP packets.
The endpoint does not create sockets, TUN interfaces, threads or a Tokio runtime.

1. Check the ABI version; create a config and client endpoint.
2. Call `covert_endpoint_advance` immediately and at least every 100 ms.
3. Feed inner IP packets to `covert_endpoint_tun_write` and complete received
   tunnel frames to `covert_endpoint_out_write`.
4. Drain `covert_endpoint_read_outbound` to `COVERT_EMPTY`, wrapping frames in
   ICMP requests when using a ping socket; drain `covert_endpoint_tun_read` to
   `COVERT_EMPTY` and write the resulting IP packets to the host TUN.
5. Read `covert_endpoint_status` for live state, plaintext byte counts and
   establishment times. Free returned buffers and handles.

All calls to a given handle must be serialized. Frame inputs exclude UDP, ICMP,
and outer IP headers. Input to `out_write` must contain exactly one frame;
malformed or unauthenticated input returns `COVERT_FAILED`, ignored packets return
`COVERT_EMPTY`. Both are nonfatal network input; discard the handle on
`COVERT_PANIC`. The host must bound application traffic submitted before a
handshake completes; Android continues dropping it until connected.

Received bytes count plaintext drained through `tun_read`, rather than successful
TUN writes; sent bytes count plaintext accepted through `tun_write`. Handshakes
and keepalives do not contribute. All owned buffers are freed with
`covert_buffer_free`, never C's `free`.

Android keeps protection/network binding, ICMP framing, polling, cancellation
and JNI callbacks in its C/Java layer. Rust owns authentication, sessions,
packet routing and statistics. `covert_android_init_logging` installs Logcat
tracing; it is a no-op on host builds and preserves an existing subscriber.

The FFI is split into `codec.rs`, `config.rs`, `crypto.rs`, `endpoint.rs` and
`tunnel.rs` under `src/ffi/`; `src/ffi.rs` only holds shared ABI utilities.

## Verification

`just test-ffi` builds the host library and runs the crypto/codec/tunnel,
endpoint and main-config C ABI tests. The latter checks setters/getters, peer
indices, liveness inheritance, failed setter atomicity and endpoint ownership.

The Android project's `scripts/test-native.sh` additionally runs Rust tests and
the real JNI loopback test, including native config ownership and closed-handle
checks. `scripts/test-icmp-server.sh /path/to/covert` checks an Android-style ping
socket against the CLI and a real TUN in a disposable Linux network namespace.
Neither workflow uses an emulator.

`covert_config_from_query(data, len, &config)` parses UTF-8 query parameters with
`Config::from_query`; pass only the query, without `covert:/?`, and preserve its
percent encoding. It returns a new owned handle (null on failure). Free it with
`covert_config_free`. `covert_config_to_json(config, &buffer)` exports the same
config as UTF-8 JSON; free the output with `covert_buffer_free`. Both query and
JSON contain private key material. Android imports configuration links as owned
Config handles and reads their fields through getters, without a JSON conversion.
It asks for confirmation before saving the resulting profile.
