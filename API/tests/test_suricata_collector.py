import json
import os

from fastapi.testclient import TestClient

from app.main import app
from controller.suricata_collector import relevant, scan


def alert(signature='ET MALWARE test indicator'):
    return {'event_type': 'alert', 'timestamp': '2026-11-20T10:00:00+0000',
            'src_ip': '192.0.2.1', 'dest_ip': '198.51.100.1',
            'alert': {'signature': signature, 'severity': 2},
            'http': {'url': '/private-data'}}


def test_collector_starts_at_end_minimizes_data_and_handles_rotation(tmp_path):
    path = tmp_path / 'eve.json'
    path.write_text(json.dumps(alert()) + '\n')
    cursor, events = scan(path, None)
    assert events == []
    with path.open('a') as f:
        f.write(json.dumps(alert('ET SCAN unrelated')) + '\n')
        f.write(json.dumps(alert()) + '\n')
        f.write('{"event_type":')
    cursor, events = scan(path, cursor)
    assert len(events) == 1 and 'http' not in events[0]
    assert events[0]['timestamp'] == '2026-11-20T10:00:00+00:00'
    assert path.read_bytes()[cursor['offset']:] == b'{"event_type":'
    path.rename(tmp_path / 'eve.json.1')
    path.write_text(json.dumps(alert('ET EXPLOIT test')) + '\n')
    _, events = scan(path, cursor)
    assert events[0]['alert']['signature'] == 'ET EXPLOIT test'


def test_collector_rejects_malformed_alerts():
    bad = alert()
    bad['src_ip'] = 'invalid'
    assert relevant(json.dumps(bad)) is None
    bad = alert()
    bad['alert']['severity'] = 'bad'
    assert relevant(json.dumps(bad)) is None


def test_internal_ingest_requires_explicit_enable_and_validates_batch(monkeypatch):
    client = TestClient(app)
    monkeypatch.delenv('NETSHIELD_SURICATA_INGEST', raising=False)
    assert client.post('/internal/suricata/alerts', json={'events': [alert()]}).status_code == 404
    monkeypatch.setenv('NETSHIELD_SURICATA_INGEST', '1')
    saved = []
    monkeypatch.setattr('app.infrastructure.alerts.PostgresAlerts.save', lambda self, obj: saved.append(obj) or True)
    response = client.post('/internal/suricata/alerts', json={'events': [alert()]})
    assert response.status_code == 200 and response.json() == {'inserted': 1}
    assert len(saved) == 1
    response = client.post('/internal/suricata/alerts', json={'events': [alert(), {'event_type': 'dns'}]})
    assert response.status_code == 422 and len(saved) == 1
