# porto

a simple but fast reverse proxy with TLS termination

## Features

- Custom connection pool for blazingly fast performance
- Proxying to UDS and TCP sockets
- HTTPS support with rustls
- ACME support for automatic certificate renewal
- CLI and config file parsing with clap
- HTTP based control interface
- Response caching according to RFC 7234
- Response compression
- Health checks
- Custom rate limiter using a token bucket
- systemd interation

## WIP

- Load Balancing
- Notifications/Metrics

## Hello World

build it with cargo

```
git clone https://github.com/Reza-Darius/porto
cargo build
porto start 127.0.0.1:4000
```

By default, porto looks for a `porto.toml` in the current working directory. Alternative a location can be provided by passing `-c path/to/config`

## CLI

```
porto run - starts the porto proxy
porto stop - shuts down a running porto server
porto status - fetches information about a running porto server
```

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

# optional settings
http2 = true
rate_limit_enable = false

[[proxy]]
domain = "GolangIsCoolToo.com"
upstream = "/tmp/website.sock"
```
