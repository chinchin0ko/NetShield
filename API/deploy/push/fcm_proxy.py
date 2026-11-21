"""Loopback-only HTTP CONNECT relay for the two endpoints used by FCM.

TLS is end-to-end between the API worker and Google; this relay never decrypts
requests. Access from the private API host is through a restricted SSH forward.
"""
import asyncio

ALLOWED_HOSTS = frozenset({'oauth2.googleapis.com', 'fcm.googleapis.com'})


def destination(line):
    try:
        method, authority, version = line.decode('ascii').strip().split(' ')
        host, port = authority.rsplit(':', 1)
    except (UnicodeDecodeError, ValueError):
        return None
    if method != 'CONNECT' or version not in ('HTTP/1.0', 'HTTP/1.1') or port != '443' or host not in ALLOWED_HOSTS:
        return None
    return host


async def copy(source, target):
    try:
        while data := await asyncio.wait_for(source.read(65536), timeout=90):
            target.write(data)
            await target.drain()
    except (OSError, asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        target.close()


async def handle(reader, writer):
    upstream = None
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=5)
        host = destination(line)
        if host is None:
            writer.write(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
            await writer.drain()
            return
        total = 0
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            total += len(line)
            if not line or total > 16384:
                return
            if line in (b'\r\n', b'\n'):
                break
        remote, upstream = await asyncio.wait_for(asyncio.open_connection(host, 443), timeout=10)
        writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        await writer.drain()
        await asyncio.gather(copy(reader, upstream), copy(remote, writer))
    except (OSError, ValueError, asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()
        if upstream is not None:
            upstream.close()


async def main():
    async with await asyncio.start_server(handle, '127.0.0.1', 18888, limit=16384) as server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
