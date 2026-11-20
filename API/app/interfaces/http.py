"""HTTP adapter: maps requests and responses to application use cases."""
import psycopg
import os
import re
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.application.auth import AuthService, AuthenticationError, LoginRateLimited
from app.composition import get_auth_service, get_device_service
from app.application.devices import DeviceService, InvalidDevice, DeviceAlreadyExists

router = APIRouter()
bearer = HTTPBearer(auto_error=False)


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class NewAccount(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r'^[a-zA-Z0-9_.-]+$')
    password: str = Field(min_length=12, max_length=128)


@router.post('/auth/register', status_code=201)
def register_account(data: NewAccount, service: AuthService = Depends(get_auth_service)):
    # Explicit opt-in for the development environment.
    if os.environ.get('NETSHIELD_DEV_REGISTRATION') != '1':
        raise HTTPException(status_code=404, detail='Not found')
    try:
        service.create_user(data.username, data.password)
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail='Username unavailable') from None
    return {'message': 'Account created'}


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
def login(credentials: Credentials, response: Response, service: AuthService = Depends(get_auth_service)):
    try:
        token = service.login(credentials.username, credentials.password)
    except LoginRateLimited as exc:
        raise HTTPException(status_code=429, detail='Too many attempts', headers={'Retry-After': str(exc.retry_after), 'Cache-Control': 'no-store'}) from None
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid credentials") from None
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail='Authentication unavailable') from None
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
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


class VPNRequest(BaseModel):
    device_id: str = Field(pattern=r'^[0-9a-f]{32}$')
    public_key: str = Field(min_length=44, max_length=44)


@router.post('/vpn/config')
def vpn_config(data: VPNRequest, response: Response, user=Depends(current_identity)):
    from app.infrastructure.wg_easy_bridge import provision, ProvisioningError, DeviceRevoked, DeviceKeyConflict, DeviceLimitReached
    from app.application.vpn_peers import PeerService
    try:
        PeerService._key(data.public_key)
        config = provision(user.id, data.device_id, data.public_key)
    except ValueError:
        raise HTTPException(status_code=422, detail='Invalid public key') from None
    except ProvisioningError:
        raise HTTPException(status_code=503, detail='VPN unavailable') from None
    except DeviceRevoked:
        raise HTTPException(status_code=403, detail='Device revoked') from None
    except DeviceKeyConflict:
        raise HTTPException(status_code=409, detail='Device key already in use') from None
    except DeviceLimitReached:
        raise HTTPException(status_code=409, detail='Device limit reached') from None
    response.headers['Cache-Control'] = 'no-store'
    return {'config': config}


@router.get('/vpn/devices')
def vpn_devices(user=Depends(current_identity)):
    from app.infrastructure.wg_easy_bridge import list_devices, ProvisioningError
    try:
        return {'devices': list_devices(user.id)}
    except ProvisioningError:
        raise HTTPException(status_code=503, detail='VPN unavailable') from None


@router.post('/vpn/devices/{device_id}/revoke', status_code=204)
def revoke_vpn_device(device_id: str, user=Depends(current_identity)):
    from app.infrastructure.wg_easy_bridge import revoke, ProvisioningError
    if not re.fullmatch(r'[0-9a-f]{32}', device_id):
        raise HTTPException(status_code=422, detail='Invalid device ID')
    try:
        if not revoke(user.id, device_id):
            raise HTTPException(status_code=404, detail='Device not found')
    except ProvisioningError:
        raise HTTPException(status_code=503, detail='VPN unavailable') from None


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
