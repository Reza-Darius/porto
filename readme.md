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

## Install

it is recommended to use the install script

```bash
curl -fsSL https://raw.githubusercontent.com/reza-darius/porto/main/script/install.sh | sudo bash
```

Porto looks for a `porto.toml` in `/etc/porto/`.

Once configured run:

```bash
sudo systemctl enable --now porto
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
