"""Lab-only routes; deliberately not imported by the production application."""
from fastapi import APIRouter, Depends, HTTPException

from app.application.devices import DeviceService
from app.composition import get_device_service
from app.interfaces.http import current_identity


def create_lab_router(connections):
    router = APIRouter(prefix='/lab')

    def owned_device(device_id, user, devices):
        match = next((item for item in devices.list(user.id) if item.id == device_id), None)
        if match is None:
            raise HTTPException(status_code=404, detail='Device not found')
        return match

    @router.post('/devices/{device_id}/connect')
    def connect(device_id: int, user=Depends(current_identity),
                devices: DeviceService = Depends(get_device_service)):
        device = owned_device(device_id, user, devices)
        try:
            connections.status(user.id, device_id)
        except LookupError:
            connections.register(device.id, user.id, device.public_key)
        try:
            address = connections.connect(user.id, device_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return {'state': 'ready', 'address': address}

    @router.post('/devices/{device_id}/revoke')
    def revoke(device_id: int, user=Depends(current_identity),
               devices: DeviceService = Depends(get_device_service)):
        owned_device(device_id, user, devices)
        try:
            connections.revoke(user.id, device_id)
        except LookupError:
            raise HTTPException(status_code=404, detail='Connection not found') from None
        return {'state': 'revoked'}

    return router
