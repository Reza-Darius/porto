# porto

a simple but fast reverse proxy with TLS termination

## Features

- Async with Tokio
- HTTP upstreaming with hyper 
- dynamic support for UDS and TCP sockets
- Tower for middleware
- Deadpool for connection pooling
- HTTPS support with rustls
- ACME support for automatic certificate renewal
- CLI and config file parsing with clap
- Logging with tracing

## WIP

- Response Caching
- Rate Limiting
- Health checks
