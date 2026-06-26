# Porto

An easy to use and fast reverse proxy with TLS termination!

## Features

- Custom connection pool for blazingly fast performance
- Proxying to UDS and TCP sockets
- HTTPS support with rustls
- ACME support for automatic certificate renewal (experimental)
- Easy to use CLI and config
- HTTP based control interface
- Response caching according to RFC 7234
- Response compression
- Health checks
- Custom rate limiter using a token bucket
- Systemd integration

## WIP

- Load Balancing
- Notifications/Metrics

## Installation

### Script (recommended)

This is the recommended way for most users

```bash
curl -fsSL https://raw.githubusercontent.com/Reza-Darius/porto/main/scripts/install.sh | sudo bash
```

### From source

This method requires `cargo`

```Bash
git clone "https://github.com/Reza-Darius/porto"
cd porto
sudo make install
```

## Config and start

Porto looks for a `porto.toml` in `/etc/porto/`. To edit it run `porto config`.

Once configured run:

```bash
sudo systemctl enable --now porto
```

To stop the server run either `porto stop` or `systemctl stop porto`

## Config file details

```toml
# address for Porto to listen on
bind = "127.0.0.1:3000"

[tls]
tls = true

# enables ACME for automatic certificates, make sure Porto is allowed to bind to port 80
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

With this configuration Porto serves HTTPS requests arriving on localhost:3000
and proxies them according to the domain in the request.
