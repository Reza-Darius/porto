server_addr := "127.0.0.1:4000"

cap:
    sudo setcap 'cap_net_bind_service=+ep' ./target/server
    sudo setcap 'cap_net_bind_service=+ep' ./debug/server

sr:
    cargo run --release --bin server -- {{ server_addr }}

s:
    cargo run --bin server -- {{ server_addr }}

pr:
    cargo run --release --bin peer

p:
    cargo run --bin peer

c:
    curl --resolve testpeer.com:4000:127.0.0.1 \
      https://testpeer.com:4000/ \
      -H "Accept-Encoding: gzip" \
      -v
