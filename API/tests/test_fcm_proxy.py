from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[1] / 'deploy' / 'push' / 'fcm_proxy.py'
spec = spec_from_file_location('fcm_proxy', path)
proxy = module_from_spec(spec)
spec.loader.exec_module(proxy)


@pytest.mark.parametrize('line,expected', [
    (b'CONNECT fcm.googleapis.com:443 HTTP/1.1\r\n', 'fcm.googleapis.com'),
    (b'CONNECT oauth2.googleapis.com:443 HTTP/1.1\r\n', 'oauth2.googleapis.com'),
    (b'CONNECT fcm.googleapis.com.evil.test:443 HTTP/1.1\r\n', None),
    (b'CONNECT fcm.googleapis.com:80 HTTP/1.1\r\n', None),
    (b'GET fcm.googleapis.com:443 HTTP/1.1\r\n', None),
    (b'CONNECT 127.0.0.1:443 HTTP/1.1\r\n', None),
    (b'CONNECT fcm.googleapis.com:443 HTTP/2\r\n', None),
    (b'\xff\r\n', None),
])
def test_only_firebase_and_oauth_tls_are_allowed(line, expected):
    assert proxy.destination(line) == expected
