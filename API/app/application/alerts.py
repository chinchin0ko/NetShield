"""Convert Suricata EVE alerts to a minimal, deduplicated alert record."""
import hashlib
import ipaddress
import json
from datetime import datetime
from typing import Protocol

from app.domain.alerts import SecurityAlert


class AlertRepository(Protocol):
    def save(self, alert: SecurityAlert) -> bool: ...


class InvalidAlert(ValueError):
    pass


def parse_alert(line: str) -> SecurityAlert | None:
    try:
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError('Expected JSON object')
        if event.get('event_type') != 'alert':
            return None
        details = event['alert']
        signature = details['signature']
        severity = details['severity']
        occurred_at = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
        if (not isinstance(signature, str) or not 1 <= len(signature) <= 1024
                or type(severity) is not int or not 1 <= severity <= 255
                or occurred_at.tzinfo is None):
            raise ValueError('Invalid alert data')
        def ip(value):
            return str(ipaddress.ip_address(value)) if value is not None else None
        source, destination = ip(event.get('src_ip')), ip(event.get('dest_ip'))
        canonical = json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
        return SecurityAlert(hashlib.sha256(canonical.encode()).hexdigest(), occurred_at,
                             signature, severity, source, destination)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError) as exc:
        raise InvalidAlert('Invalid Suricata event') from exc


class AlertService:
    def __init__(self, alerts: AlertRepository):
        self.alerts = alerts

    def ingest(self, line: str) -> bool:
        alert = parse_alert(line)
        return self.alerts.save(alert) if alert else False
