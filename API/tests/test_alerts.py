import json
import pytest
from app.application.alerts import AlertService, InvalidAlert, parse_alert


class MemoryAlerts:
    def __init__(self): self.hashes = set()
    def save(self, alert):
        if alert.event_hash in self.hashes: return False
        self.hashes.add(alert.event_hash)
        return True


def test_alert_parsing_and_deduplication():
    event = {'event_type': 'alert', 'timestamp': '2026-11-17T10:00:00+0000',
             'src_ip': '192.0.2.1', 'dest_ip': '192.0.2.2',
             'alert': {'signature': 'Example', 'severity': 2}}
    service = AlertService(MemoryAlerts())
    assert service.ingest(json.dumps(event)) is True
    assert service.ingest(json.dumps(event, indent=2)) is False
    assert service.ingest('{"event_type":"dns"}') is False
    assert parse_alert(json.dumps(event)).source_ip == '192.0.2.1'


def test_reject_invalid_alert():
    with pytest.raises(InvalidAlert): parse_alert('{"event_type":"alert"}')
    with pytest.raises(InvalidAlert): parse_alert('not json')
