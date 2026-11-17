"""HTTP adapter: maps requests and responses to application use cases."""
import psycopg
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.application.auth import AuthService, AuthenticationError
from app.composition import get_auth_service, get_device_service
from app.application.devices import DeviceService, InvalidDevice, DeviceAlreadyExists

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


class DeviceRegistration(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    public_key: str = Field(min_length=44, max_length=44)


def current_identity(credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
                     service: AuthService = Depends(get_auth_service)):
    if credentials is None or credentials.scheme.lower() != 'bearer':
        raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate': 'Bearer'})
    try:
        return service.current_identity(credentials.credentials)
    except AuthenticationError:
        raise HTTPException(status_code=401, detail='Invalid token', headers={'WWW-Authenticate': 'Bearer'}) from None


@router.post('/devices', status_code=201)
def register_device(data: DeviceRegistration, user=Depends(current_identity),
                    service: DeviceService = Depends(get_device_service)):
    try:
        return service.register(user.id, data.name, data.public_key)
    except InvalidDevice as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except DeviceAlreadyExists:
        raise HTTPException(status_code=409, detail='Device public key already registered') from None


@router.get('/devices')
def list_devices(user=Depends(current_identity), service: DeviceService = Depends(get_device_service)):
    return service.list(user.id)


@router.delete('/devices/{device_id}', status_code=204)
def delete_device(device_id: int, user=Depends(current_identity), service: DeviceService = Depends(get_device_service)):
    if not service.delete(user.id, device_id):
        raise HTTPException(status_code=404, detail='Device not found')
