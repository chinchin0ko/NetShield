"""Use cases: no HTTP, SQL, or cryptography library dependencies."""
from app.application.ports import Passwords, Tokens, UserRepository


class AuthenticationError(Exception):
    pass


class AuthService:
    def __init__(self, users: UserRepository, passwords: Passwords, tokens: Tokens):
        self.users = users
        self.passwords = passwords
        self.tokens = tokens

    def login(self, username: str, password: str) -> str:
        user = self.users.by_username(username)
        if not user or not user.is_active or not self.passwords.verify(user.password_hash, password):
            raise AuthenticationError
        return self.tokens.create(user.id)

    def current_user(self, token: str) -> str:
        user = self.users.by_id(self.tokens.user_id(token))
        if not user or not user.is_active:
            raise AuthenticationError
        return user.username

    def create_user(self, username: str, password: str) -> None:
        self.users.create(username, self.passwords.hash(password))
