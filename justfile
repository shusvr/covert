run config="ex1":
    cargo b && sudo ./target/debug/covert run ./examples/{{quote(config)}}.toml

# Build target/release/libcovert.so (Linux). C declarations: include/covert.h.
lib:
    cargo build --release --lib
