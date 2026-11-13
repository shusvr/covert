run config="ex1":
    cargo b && sudo ./target/debug/covert run ./examples/{{quote(config)}}.toml
