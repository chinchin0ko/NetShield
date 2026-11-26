"""HTTP adapter: maps requests and responses to application use cases."""
import psycopg
import os
import re
import json
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Response, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.application.auth import AuthService, AuthenticationError, LoginRateLimited
from app.composition import get_auth_service, get_device_service
from app.application.devices import DeviceService, InvalidDevice, DeviceAlreadyExists
from app.application.alerts import AlertService, InvalidAlert, parse_alert
from app.infrastructure.alerts import PostgresAlerts

router = APIRouter()
bearer = HTTPBearer(auto_error=False)


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class NewAccount(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r'^[a-zA-Z0-9_.-]+$')
    password: str = Field(min_length=12, max_length=128)


class AlertBatch(BaseModel):
    events: list[dict] = Field(min_length=1, max_length=25)


@router.post('/internal/suricata/alerts')
def import_suricata_alerts(batch: AlertBatch):
    # Enable only on the mTLS listener; the public proxy must not route this path.
    if os.environ.get('NETSHIELD_SURICATA_INGEST') != '1':
        raise HTTPException(status_code=404, detail='Not found')
    service = AlertService(PostgresAlerts())
    inserted = 0
    try:
        serialized = [json.dumps(event) for event in batch.events]
        if any(parse_alert(event) is None for event in serialized):
            raise InvalidAlert('Only alerts are accepted')
        for event in serialized:
            inserted += int(service.ingest(event))
    except InvalidAlert:
        raise HTTPException(status_code=422, detail='Invalid alert') from None
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail='Alert storage unavailable') from None
    return {'inserted': inserted}


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
        session = service.login(credentials.username, credentials.password)
    except LoginRateLimited as exc:
        raise HTTPException(status_code=429, detail='Too many attempts', headers={'Retry-After': str(exc.retry_after), 'Cache-Control': 'no-store'}) from None
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid credentials") from None
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail='Authentication unavailable') from None
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return {"access_token": session.access_token, "refresh_token": session.refresh_token, "token_type": "bearer", "expires_in": 1800}


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(min_length=43, max_length=128)


@router.post("/auth/refresh")
def refresh_session(data: RefreshTokenRequest, response: Response, service: AuthService = Depends(get_auth_service)):
    try:
        session = service.refresh(data.refresh_token)
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from None
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail='Authentication unavailable') from None
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return {"access_token": session.access_token, "refresh_token": session.refresh_token, "token_type": "bearer", "expires_in": 1800}


@router.post("/auth/logout", status_code=204)
def logout_session(data: RefreshTokenRequest, service: AuthService = Depends(get_auth_service)):
    try:
        service.logout(data.refresh_token)
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail='Authentication unavailable') from None
    return Response(status_code=204)


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


@router.get('/vpn/usage')
def vpn_usage(response: Response, user=Depends(current_identity)):
    from app.infrastructure.wg_easy_bridge import device_usage, ProvisioningError
    try:
        devices = device_usage(user.id)
    except ProvisioningError:
        raise HTTPException(status_code=503, detail='VPN usage unavailable') from None
    response.headers['Cache-Control'] = 'no-store'
    return {'devices': devices, 'scope': 'current_wireguard_counters'}


@router.get('/vpn/usage/history')
def vpn_usage_history(response: Response, user=Depends(current_identity)):
    from app.infrastructure.usage_history import history_for_user
    try:
        days = history_for_user(user.id)
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail='VPN usage history unavailable') from None
    response.headers['Cache-Control'] = 'no-store'
    return {'days': days, 'scope': 'estimated_sampled_counters', 'timezone': 'UTC'}


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


class PushSubscription(BaseModel):
    device_id: str = Field(pattern=r'^[0-9a-f]{32}$')
    token: str = Field(min_length=1, max_length=4096, pattern=r'^[A-Za-z0-9_:.\-]+$')


@router.put('/push/subscription', status_code=204)
def register_push(data: PushSubscription, response: Response, user=Depends(current_identity)):
    from app.infrastructure.push import register
    try:
        register(user.id, data.device_id, data.token)
    except ValueError:
        raise HTTPException(status_code=429, detail='Push device limit reached') from None
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail='Push service unavailable') from None
    response.headers['Cache-Control'] = 'no-store'


@router.delete('/push/subscription/{device_id}', status_code=204)
def unregister_push(device_id: str, response: Response, user=Depends(current_identity)):
    from app.infrastructure.push import unregister
    if not re.fullmatch(r'[0-9a-f]{32}', device_id):
        raise HTTPException(status_code=422, detail='Invalid device')
    try:
        unregister(user.id, device_id)
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail='Push service unavailable') from None
    response.headers['Cache-Control'] = 'no-store'


@router.get('/security/alerts')
def personal_security_alerts(response: Response, user=Depends(current_identity)):
    from app.infrastructure.personal_alerts import PostgresPersonalAlerts
    try:
        alerts = PostgresPersonalAlerts().list_for_user(user.id)
        from app.infrastructure.postgres import database
        with database() as conn:
            row = conn.execute("SELECT last_seen > clock_timestamp() - interval '30 seconds' AND last_seen <= clock_timestamp() + interval '2 seconds' FROM vpn_sensor_heartbeat WHERE id=1").fetchone()
            monitoring = 'experimental' if row and row[0] else 'not_active'
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail='Alerts unavailable') from None
    response.headers['Cache-Control'] = 'no-store'
    return {'alerts': alerts, 'monitoring': monitoring,
            'sensor_status': 'active' if monitoring == 'experimental' else 'not_active'}


class AlertReview(BaseModel):
    status: Literal['new', 'reviewed', 'false_positive']


@router.post('/security/alerts/{alert_id}/review', status_code=204)
def review_personal_alert(alert_id: int, review: AlertReview, response: Response, user=Depends(current_identity)):
    from app.infrastructure.personal_alerts import PostgresPersonalAlerts
    if alert_id <= 0 or alert_id > 9223372036854775807:
        raise HTTPException(status_code=404, detail='Alert not found')
    try:
        found = PostgresPersonalAlerts().review_for_user(user.id, alert_id, review.status)
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail='Alert review unavailable') from None
    if not found:
        raise HTTPException(status_code=404, detail='Alert not found')
    response.headers['Cache-Control'] = 'no-store'


@router.post('/security/alerts/test', status_code=201)
def create_test_security_alert(response: Response, user=Depends(current_identity)):
    # Explicit development opt-in; the account is always derived from its token.
    if os.environ.get('NETSHIELD_DEV_ALERT_TEST') != '1':
        raise HTTPException(status_code=404, detail='Not found')
    import hashlib
    import secrets
    from app.infrastructure.postgres import database
    try:
        with database() as conn:
            conn.execute('SELECT pg_advisory_xact_lock(%s, %s)', (19111, user.id % 2147483647))
            count = conn.execute("SELECT count(*) FROM personal_security_alerts WHERE user_id = %s "
                                 "AND signature = %s AND created_at > now() - interval '1 hour'",
                                 (user.id, 'PRUEBA: alerta simulada de NetShield')).fetchone()[0]
            if count >= 5:
                raise HTTPException(status_code=429, detail='Test limit reached')
            row = conn.execute('SELECT device_id FROM vpn_address_assignments '
                               'WHERE user_id = %s AND valid_until IS NULL '
                               'ORDER BY valid_from DESC LIMIT 1', (user.id,)).fetchone()
            if row is None:
                raise HTTPException(status_code=409, detail='No active device')
            conn.execute('INSERT INTO personal_security_alerts '
                         '(event_hash, user_id, device_id, occurred_at, signature, severity) '
                         'VALUES (%s, %s, %s, clock_timestamp(), %s, %s)',
                         (hashlib.sha256(secrets.token_bytes(32)).hexdigest(), user.id, row[0],
                          'PRUEBA: alerta simulada de NetShield', 3))
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail='Alerts unavailable') from None
    response.headers['Cache-Control'] = 'no-store'
    return {'message': 'test alert created'}


class PersonalBatch(BaseModel):
    events: list[dict] = Field(default_factory=list, max_length=25)


@router.post('/internal/suricata/personal')
def ingest_personal_sensor(batch: PersonalBatch, x_netshield_sensor_key: str = Header(default='')):
    import hmac
    from app.application.assignment_lifecycle import SnapshotPeer, validate_snapshot
    from app.application.personal_alerts import ingest_current_alert, ingest_known_alert
    from app.infrastructure.assignments import PostgresAssignments
    from app.infrastructure.personal_alerts import PostgresPersonalAlerts
    from app.infrastructure.postgres import database
    from app.infrastructure.wg_easy_bridge import _request, ProvisioningError
    key = os.environ.get('NETSHIELD_PERSONAL_SENSOR_KEY', '')
    if len(key) < 40 or not hmac.compare_digest(key, x_netshield_sensor_key):
        raise HTTPException(status_code=404, detail='Not found')
    try:
        events = [json.dumps(event) for event in batch.events]
        if any(parse_alert(event) is None for event in events):
            raise InvalidAlert('Invalid event')
        store = PostgresAssignments()
        inserted = 0
        with store.exclusive():
            result = _request(1, 'snapshot', history=True)
            raw = result.get('ownership_snapshot')
            if not isinstance(raw, list): raise ValueError('invalid snapshot')
            snapshot = validate_snapshot([SnapshotPeer(**peer) for peer in raw])
            with database() as conn:
                now = conn.execute('SELECT clock_timestamp()').fetchone()[0]
            for event in events:
                alerts = PostgresPersonalAlerts()
                alert = parse_alert(event)
                if ingest_current_alert(event, store, alerts, snapshot, now):
                    inserted += 1
                    alerts.remove_hold(alert)
                else:
                    alerts.hold_if_unattributed(alert)
            # Retry a bounded, fair batch on every heartbeat. Ambiguous events
            # stay private until the same ownership checks become conclusive.
            alerts = PostgresPersonalAlerts()
            for held in alerts.pending_for_retry():
                if ingest_known_alert(held, store, alerts, snapshot, now):
                    inserted += 1
                alerts.note_checked_or_remove_delivered(held)
            with database() as conn:
                conn.execute('INSERT INTO vpn_sensor_heartbeat (id,last_seen) VALUES (1,clock_timestamp()) '
                             'ON CONFLICT (id) DO UPDATE SET last_seen=EXCLUDED.last_seen')
        return {'inserted': inserted}
    except InvalidAlert:
        raise HTTPException(status_code=422, detail='Invalid alert') from None
    except (psycopg.Error, RuntimeError, TypeError, ValueError, ProvisioningError):
        raise HTTPException(status_code=503, detail='Sensor unavailable') from None
