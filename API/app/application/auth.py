"""Use cases: no HTTP, SQL, or cryptography library dependencies."""
from app.application.ports import Passwords, Tokens, UserRepository


class AuthenticationError(Exception):
    pass


class LoginRateLimited(Exception):
    def __init__(self, retry_after: int):
        self.retry_after = retry_after


class AuthService:
    def __init__(self, users: UserRepository, passwords: Passwords, tokens: Tokens, limiter=None):
        self.users = users
        self.passwords = passwords
        self.tokens = tokens
        self.limiter = limiter

    def login(self, username: str, password: str) -> str:
        if self.limiter is not None:
            retry_after = self.limiter.consume(username)
            if retry_after:
                raise LoginRateLimited(retry_after)
        user = self.users.by_username(username)
        if user is None:
            self.passwords.verify_dummy(password)
            raise AuthenticationError
        valid_password = self.passwords.verify(user.password_hash, password)
        if not user.is_active or not valid_password:
            raise AuthenticationError
        return self.tokens.create(user.id)

    def current_identity(self, token: str):
        user = self.users.by_id(self.tokens.user_id(token))
        if not user or not user.is_active:
            raise AuthenticationError
        return user

    def current_user(self, token: str) -> str:
        return self.current_identity(token).username

    def create_user(self, username: str, password: str) -> None:
        self.users.create(username, self.passwords.hash(password))
