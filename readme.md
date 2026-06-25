# porto

a simple but fast reverse proxy with TLS termination

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
- Systemd interation

## WIP

- Load Balancing
- Notifications/Metrics

## Quick start

### Script install (recommended)

This is the recommended way for most users

```bash
curl -fsSL https://raw.githubusercontent.com/reza-darius/porto/main/scripts/install.sh | sudo bash
```

### Build from source

```Bash
git clone "https://github.com/Reza-Darius/porto"
cd porto
sudo make install
```

### Config and start

Porto looks for a `porto.toml` in `/etc/porto/`. To edit it run `porto config`.

Once configured run:

```bash
sudo systemctl enable --now porto
```
