"""Account-scoped registrations for generic mobile push notifications."""
from app.infrastructure.postgres import database


def register(user_id, device_id, token):
    with database() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended('netshield-push:' || %s::text, 0))", (user_id,))
        exists, count = conn.execute('SELECT EXISTS(SELECT 1 FROM push_subscriptions WHERE user_id=%s AND device_id=%s), '
                                     '(SELECT count(*) FROM push_subscriptions WHERE user_id=%s)',
                                     (user_id, device_id, user_id)).fetchone()
        if not exists and count >= 10:
            raise ValueError('Push device limit reached')
        # A registration token proves control of that app installation. Moving it
        # between accounts removes queued messages from the previous account.
        conn.execute('DELETE FROM push_subscriptions WHERE token=%s AND (user_id<>%s OR device_id<>%s)',
                     (token, user_id, device_id))
        conn.execute('INSERT INTO push_subscriptions (user_id, device_id, token) VALUES (%s,%s,%s) '
                     'ON CONFLICT (user_id,device_id) DO UPDATE SET token=EXCLUDED.token, updated_at=clock_timestamp()',
                     (user_id, device_id, token))


def unregister(user_id, device_id):
    with database() as conn:
        conn.execute('DELETE FROM push_subscriptions WHERE user_id=%s AND device_id=%s', (user_id, device_id))
