"""Connect application ports to infrastructure adapters."""
from app.application.auth import AuthService
from app.infrastructure.postgres import PostgresUsers
from app.infrastructure.security import Argon2Passwords, JwtTokens
from app.infrastructure.login_limiter import PostgresLoginLimiter


def get_auth_service() -> AuthService:
    return AuthService(PostgresUsers(), Argon2Passwords(), JwtTokens(), PostgresLoginLimiter())


def get_device_service():
    from app.application.devices import DeviceService
    from app.infrastructure.devices import PostgresDevices
    return DeviceService(PostgresDevices())
