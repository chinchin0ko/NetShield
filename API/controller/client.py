#!/usr/bin/env python3
"""Forward exactly one bounded request to the local development controller."""
import socket
import sys


def main():
    line = sys.stdin.buffer.readline(2049)
    if len(line) > 2048 or not line.endswith(b'\n'):
        raise SystemExit('invalid request')
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(5)
        client.connect('/run/netshield-wg-dev/control.sock')
        client.sendall(line)
        response = client.makefile('rb').readline(2049)
    if len(response) > 2048 or not response.endswith(b'\n'):
        raise SystemExit('invalid response')
    sys.stdout.buffer.write(response)


if __name__ == '__main__':
    main()
