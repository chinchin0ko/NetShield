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


def test_vpn_collector_keeps_phishing_and_command_control_alerts(tmp_path):
    path = tmp_path / 'eve.json'
    path.write_text(''.join(json.dumps(alert(name)) + '\n' for name in [
        'ET PHISHING example', 'ET CNC example', 'ET MALWARE example', 'ET SCAN unrelated']))
    cursor = {'inode': path.stat().st_ino, 'offset': 0}
    _, old_feed = scan(path, cursor)
    _, vpn_feed = scan(path, cursor, include_network_threats=True)
    assert [item['alert']['signature'] for item in old_feed] == ['ET MALWARE example']
    assert [item['alert']['signature'] for item in vpn_feed] == [
        'ET PHISHING example', 'ET CNC example', 'ET MALWARE example']


def test_vpn_pending_log_is_replayed_after_delivery_failure(tmp_path, monkeypatch):
    import sys
    from controller import suricata_collector, vpn_sensor_logrotate
    monkeypatch.setitem(sys.modules, 'suricata_collector', suricata_collector)
    monkeypatch.setitem(sys.modules, 'vpn_sensor_logrotate', vpn_sensor_logrotate)
    from controller import vpn_sensor_collector as collector
    eve = tmp_path / 'eve.json'
    eve.write_text('')
    pending = tmp_path / 'eve.pending.00000000000000000001.999999999'
    pending.write_text(json.dumps(alert()) + '\n')
    state = tmp_path / 'cursor.json'
    monkeypatch.setattr(collector, 'EVE', eve)
    monkeypatch.setattr(collector.common, 'STATE', state)
    monkeypatch.setattr(collector, 'sensor_pid', lambda: os.getpid())
    def failure(events):
        raise OSError('offline')
    monkeypatch.setattr(collector, 'send', failure)
    import pytest
    with pytest.raises(OSError):
        collector.process_one(None)
    assert pending.exists() and not state.exists()
    sent = []
    monkeypatch.setattr(collector, 'send', lambda events: sent.extend(events))
    cursor, had_events = collector.process_one(None)
    assert had_events and len(sent) == 1
    assert json.loads(state.read_text()) == cursor
    assert not pending.exists()
