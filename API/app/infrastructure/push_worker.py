"""Deliver the transactional alert outbox to FCM; credentials stay on the server."""
import logging
import os
import time

import google.auth
import google.auth.transport.requests
import requests

from app.infrastructure.postgres import database

LOG = logging.getLogger(__name__)
SCOPE = 'https://www.googleapis.com/auth/firebase.messaging'


class FcmSender:
    def __init__(self, project_id):
        if not project_id or not all(c.isalnum() or c == '-' for c in project_id):
            raise ValueError('A valid Firebase project ID is required')
        self.url = f'https://fcm.googleapis.com/v1/projects/{project_id}/messages:send'
        self.credentials, _ = google.auth.default(scopes=[SCOPE])
        self.session = google.auth.transport.requests.AuthorizedSession(self.credentials)

    def send(self, token):
        response = self.session.post(self.url, json={'message': {
            'token': token,
            'notification': {'title': 'NetShield VPN', 'body': 'Tienes una alerta de seguridad nueva. Abre NetShield para revisarla.'},
            'android': {'priority': 'normal', 'notification': {'channel_id': 'security_alerts'}},
        }}, timeout=10)
        if response.ok:
            return 'sent'
        if response.status_code == 404:
            try:
                details = response.json().get('error', {}).get('details', [])
                if any(d.get('errorCode') == 'UNREGISTERED' for d in details if isinstance(d, dict)):
                    return 'unregistered'
            except (ValueError, AttributeError):
                pass
        return 'retry'


def deliver_one(sender):
    # A lock is held until FCM responds so multiple workers do not concurrently
    # deliver the same item. A crash after delivery can still cause a duplicate.
    with database() as conn:
        row = conn.execute('SELECT o.alert_id,o.subscription_id,s.token FROM push_outbox o '
                           'JOIN push_subscriptions s ON s.id=o.subscription_id '
                           'WHERE o.next_attempt_at <= clock_timestamp() '
                           'ORDER BY o.next_attempt_at FOR UPDATE OF o,s SKIP LOCKED LIMIT 1').fetchone()
        if row is None:
            return False
        alert_id, subscription_id, token = row
        try:
            outcome = sender.send(token)
        except (requests.RequestException, google.auth.exceptions.GoogleAuthError):
            outcome = 'retry'
        if outcome == 'sent':
            conn.execute('DELETE FROM push_outbox WHERE alert_id=%s AND subscription_id=%s', (alert_id, subscription_id))
        elif outcome == 'unregistered':
            conn.execute('DELETE FROM push_subscriptions WHERE id=%s', (subscription_id,))
        else:
            conn.execute("UPDATE push_outbox SET attempts=attempts+1, next_attempt_at=clock_timestamp() + "
                         "make_interval(secs => LEAST(3600, 10 * power(2, LEAST(attempts, 8)))::double precision) "
                         'WHERE alert_id=%s AND subscription_id=%s', (alert_id, subscription_id))
        return True


def main():
    logging.basicConfig(level=logging.INFO)
    sender = FcmSender(os.environ.get('NETSHIELD_FIREBASE_PROJECT', ''))
    while True:
        try:
            if not deliver_one(sender):
                time.sleep(5)
        except Exception:
            LOG.exception('Push delivery failed; retrying')
            time.sleep(10)


if __name__ == '__main__':
    main()
