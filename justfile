addr := "127.0.0.1:4000"

sr:
    export RUST_LOG=error
    cargo run --release --bin server -- {{ addr }}

s:
    export RUST_LOG=debug
    cargo run --bin server -- {{ addr }}

pr:
    export RUST_LOG=error
    cargo run --release --bin peer

p:
    export RUST_LOG=debug
    cargo run --bin peer

c:
    curl --resolve testpeer.com:4000:127.0.0.1 \
      https://testpeer.com:4000/ \
      -H "Accept-Encoding: gzip" \
      -v
