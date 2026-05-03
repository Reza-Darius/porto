# porto

a simple but fast reverse proxy with TLS termination

## Features

- HTTP upstreaming with hyper, tokio and tower
- Custom connection pool
- Proxying to UDS and TCP sockets
- HTTPS support with rustls
- ACME support for automatic certificate renewal
- CLI and config file parsing with clap
- Response caching according to RFC 7234
- Logging with tracing
- Response Compression

## WIP

- Rate Limiting
- Health checks

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

# TLS is enabled by default
tls = true

# enables ACME
auto_cert = false

# if TLS is enabled, you need to provide paths for certificates
cert_path = "credentials/testpeer.com.pem"
key_path = "credentials/testpeer.com-key.pem"

# provide any number of addresses to proxy to

[[proxy]]
domain = "RustIsAwsome.com"
upstream = "127.0.0.10:4000"

[[proxy]]
domain = "GolangIsCoolToo.com"
upstream = "/tmp/website.sock"
```
