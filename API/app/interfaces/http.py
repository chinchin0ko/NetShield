"""HTTP adapter: maps requests and responses to application use cases."""
import psycopg
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.application.auth import AuthService, AuthenticationError
from app.composition import get_auth_service

router = APIRouter()
bearer = HTTPBearer(auto_error=False)


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


@router.get("/health/live")
def liveness():
    return {"status": "ok"}


@router.get("/health/ready")
def readiness(service: AuthService = Depends(get_auth_service)):
    try:
        service.users.ping()
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail="Database unavailable") from None
    return {"status": "ok"}


@router.post("/auth/token")
def login(credentials: Credentials, service: AuthService = Depends(get_auth_service)):
    try:
        token = service.login(credentials.username, credentials.password)
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid credentials") from None
    return {"access_token": token, "token_type": "bearer", "expires_in": 1800}


@router.get("/users/me")
def me(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), service: AuthService = Depends(get_auth_service)):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    try:
        username = service.current_user(credentials.credentials)
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"}) from None
    return {"username": username}
