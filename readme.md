# porto

a simple but fast reverse proxy with TLS termination

## Features

- Custom connection pool for blazingly fast performance
- Proxying to UDS and TCP sockets
- HTTPS support with rustls
- ACME support for automatic certificate renewal
- CLI and config file parsing with clap
- Response caching according to RFC 7234
- Response compression
- Health checks
- Custom rate limiter using a token bucket

## WIP

- Load Balancing
- Notifications/Metrics

## Hello World

build it with cargo

```
git clone https://github.com/Reza-Darius/porto
cargo build
```

By default, porto looks for a `porto.toml` in the current working directory. An alternate location can be provided by passing `--config "path/porto.toml"`

## Config

```toml
# address for porto to listen on
bind = "127.0.0.1:3000"

[tls]
tls = true

# enables ACME for automatic certificates, make sure porto is allowed to bind to port 80
auto_cert = false

# if TLS is enabled, and ACME disabled, you need to provide paths for certificates
cert_path = "credentials/testpeer.com.pem"
key_path = "credentials/testpeer.com-key.pem"

# provide any number of addresses to proxy to

[[proxy]]
domain = "RustIsAwsome.com"
upstream = "127.0.0.10:4000"
# optional flag
http2 = true

[[proxy]]
domain = "GolangIsCoolToo.com"
upstream = "/tmp/website.sock"
```
