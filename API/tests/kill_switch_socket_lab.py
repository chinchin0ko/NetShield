"""Helper for disposable namespace test; no production connections."""
import socket
import sys
import time
from pathlib import Path

role, folder = sys.argv[1], Path(sys.argv[2])
if role == 'server':
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('fd42::2', 45444))
        server.listen(1)
        (folder / 'server-ready').touch()
        connection, _ = server.accept()
        with connection:
            connection.settimeout(15)
            try: connection.recv(1)
            except OSError: pass
elif role == 'client':
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(('fd42::2', 45444))
        (folder / 'client-ready').touch()
        try:
            data = client.recv(1)
            if not data: (folder / 'client-closed').touch()
        except OSError:
            (folder / 'client-closed').touch()
elif role == 'loopback':
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server:
        server.bind(('::1', 0)); server.listen(1)
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
            client.connect(server.getsockname())
            connection, _ = server.accept()
            with connection:
                (folder / 'loopback-ready').touch()
                time.sleep(3)
                client.sendall(b'x')
                connection.settimeout(2)
                if connection.recv(1) == b'x': (folder / 'loopback-intact').touch()
else:
    raise ValueError('invalid role')
