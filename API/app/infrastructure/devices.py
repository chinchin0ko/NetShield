from psycopg.errors import UniqueViolation

from app.application.devices import DeviceAlreadyExists
from app.domain.devices import Device
from app.infrastructure.postgres import database


class PostgresDevices:
    def create(self, user_id, name, public_key):
        try:
            with database() as conn:
                row = conn.execute(
                    'INSERT INTO devices (user_id, name, public_key) VALUES (%s, %s, %s) '
                    'RETURNING id, user_id, name, public_key, created_at',
                    (user_id, name, public_key),
                ).fetchone()
        except UniqueViolation:
            raise DeviceAlreadyExists from None
        return Device(*row)

    def list_for_user(self, user_id):
        with database() as conn:
            rows = conn.execute(
                'SELECT id, user_id, name, public_key, created_at FROM devices WHERE user_id = %s ORDER BY id',
                (user_id,),
            ).fetchall()
        return [Device(*row) for row in rows]

    def delete(self, user_id, device_id):
        with database() as conn:
            row = conn.execute('DELETE FROM devices WHERE id = %s AND user_id = %s RETURNING id',
                               (device_id, user_id)).fetchone()
        return row is not None
