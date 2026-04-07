import socket
import ssl
import threading

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 3000
CERT_FILE = "RezaDarius.de+2.pem"
KEY_FILE = "RezaDarius.de+2-key.pem"
UDS_PATH = "/tmp/darius_art.sock"
TARGET_HOST = "RezaDarius.de"


def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        try:
            src.close()
        except:
            pass
        try:
            dst.close()
        except:
            pass


def handle(client_sock):
    # peek at Host header to validate
    data = client_sock.recv(4096, socket.MSG_PEEK)
    if TARGET_HOST.lower().encode() not in data.lower():
        client_sock.close()
        return

    backend = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        backend.connect(UDS_PATH)
    except Exception as e:
        print(f"backend connect failed: {e}")
        client_sock.close()
        return

    t1 = threading.Thread(target=forward, args=(client_sock, backend), daemon=True)
    t2 = threading.Thread(target=forward, args=(backend, client_sock), daemon=True)
    t1.start()
    t2.start()


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT_FILE, KEY_FILE)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((LISTEN_HOST, LISTEN_PORT))
server.listen(128)
server = ctx.wrap_socket(server, server_side=True)

print(f"listening on {LISTEN_HOST}:{LISTEN_PORT}")
while True:
    client, addr = server.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
