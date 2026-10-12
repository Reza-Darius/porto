cap:
    sudo setcap 'cap_net_bind_service=+ep' ./target/server
    sudo setcap 'cap_net_bind_service=+ep' ./debug/server

build-server:
    cargo build --release --bin porto

s:
    cargo run -- start -c . -d

sr: build-server
    ./target/release/porto start -c . -d

pr:
    cargo run --release --bin peer

p:
    cargo run --bin peer

t:
    cargo test --test service-test -- --show-output

install: build-server
    sudo install -o root -g root -m 755 target/release/porto /usr/local/bin/porto
    sudo systemctl restart porto

test_acme:
    docker compose up -d
    cargo test acme_test -- --ignored --no-capture
    curl --http1.1 --resolve acmetest.com:8000:127.0.0.1 https://acmetest.com:8000 -k -v
    docker compose down
