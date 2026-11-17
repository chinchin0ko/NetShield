"""Connect application ports to infrastructure adapters."""
from app.application.auth import AuthService
from app.infrastructure.postgres import PostgresUsers
from app.infrastructure.security import Argon2Passwords, JwtTokens


def get_auth_service() -> AuthService:
    return AuthService(PostgresUsers(), Argon2Passwords(), JwtTokens())
