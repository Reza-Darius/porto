import asyncio
import ssl

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 3000
CERT_FILE = "example_cert.pem"
KEY_FILE = "example_key.pem"
UDS_PATH = "/tmp/darius_art.sock"
TARGET_HOST = "rezadarius.de"


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except:
        pass
    finally:
        try:
            writer.close()
        except:
            pass


async def handle(reader, writer):
    # read request head
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = await reader.read(4096)
        if not chunk:
            writer.close()
            return
        head += chunk

    # parse host header
    host = None
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"host:"):
            host = line.split(b":", 1)[1].strip().lower().decode()
            break

    if host != TARGET_HOST:
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()
        writer.close()
        return

    # connect to backend UDS
    try:
        be_reader, be_writer = await asyncio.open_unix_connection(UDS_PATH)
    except Exception as e:
        print(f"backend connect failed: {e}")
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await writer.drain()
        writer.close()
        return

    # forward the already-read head, then pipe both directions
    be_writer.write(head)
    await be_writer.drain()

    await asyncio.gather(
        pipe(reader, be_writer),
        pipe(be_reader, writer),
    )


async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)

    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT, ssl=ctx)
    print(f"listening on {LISTEN_HOST}:{LISTEN_PORT}")
    async with server:
        await server.serve_forever()


asyncio.run(main())
