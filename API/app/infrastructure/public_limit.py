"""Bounded, process-local request limits for the single development API worker."""
import ipaddress
import os
import time

from starlette.responses import JSONResponse


class PublicLimit:
    def __init__(self, app, clock=time.monotonic, capacity=10000):
        self.app, self.clock, self.capacity = app, clock, capacity
        self.windows = {}

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or os.environ.get('NETSHIELD_PUBLIC_LIMIT') != '1':
            return await self.app(scope, receive, send)
        # This header is authoritative only on the mTLS listener, behind Caddy
        # configured to replace it with the actual socket peer's address.
        values = [v for k, v in scope['headers'] if k.lower() == b'x-netshield-client-ip']
        try:
            if len(values) != 1:
                raise ValueError
            address = str(ipaddress.ip_address(values[0].decode('ascii')))
        except (ValueError, UnicodeDecodeError):
            return await JSONResponse({'detail': 'Invalid client address'}, status_code=400)(scope, receive, send)
        now = self.clock()
        if len(self.windows) >= self.capacity:
            self.windows = {key: value for key, value in self.windows.items() if value[1] > now}
        group = {'/auth/token': 'login', '/auth/refresh': 'login', '/auth/register': 'registration'}.get(scope['path'], 'general')
        key = (address, group)
        if key not in self.windows and len(self.windows) >= self.capacity:
            return await JSONResponse({'detail': 'Service busy'}, status_code=503)(scope, receive, send)
        count, expires = self.windows.get(key, (0, now + 60))
        if expires <= now:
            count, expires = 0, now + 60
        count += 1
        self.windows[key] = (count, expires)
        if count > {'login': 20, 'registration': 5, 'general': 120}[group]:
            return await JSONResponse({'detail': 'Too many requests'}, status_code=429,
                                      headers={'Retry-After': str(max(1, int(expires - now))), 'Cache-Control': 'no-store'})(scope, receive, send)
        return await self.app(scope, receive, send)
