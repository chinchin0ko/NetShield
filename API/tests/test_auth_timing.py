import pytest
from app.application.auth import AuthService, AuthenticationError
from app.domain.users import User


class Users:
    def __init__(self, user): self.user = user
    def by_username(self, username): return self.user


class Passwords:
    def __init__(self): self.calls = []
    def verify(self, password_hash, password):
        self.calls.append(('verify', password_hash))
        return False
    def verify_dummy(self, password): self.calls.append(('dummy',))


def test_missing_user_still_runs_password_verification():
    passwords = Passwords()
    with pytest.raises(AuthenticationError):
        AuthService(Users(None), passwords, None).login('unknown', 'password')
    assert passwords.calls == [('dummy',)]


def test_disabled_user_still_verifies_password():
    passwords = Passwords()
    user = User(1, 'alice', 'hash', False)
    with pytest.raises(AuthenticationError):
        AuthService(Users(user), passwords, None).login('alice', 'password')
    assert passwords.calls == [('verify', 'hash')]
