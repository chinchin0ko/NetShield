import json
from datetime import datetime, timezone
from ipaddress import IPv4Address
from app.application.attribution import Assignment
from app.application.personal_alerts import ingest_personal_alert


def test_attribution_rejects_untrusted_and_ambiguous_evidence():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    owner = Assignment(IPv4Address('10.8.0.2'), 1, 'a'*32, now)
    class Assignments:
        values = [owner]
        def find_at(self, address, timestamp): return self.values
    class Alerts:
        saved = []
        def save_for_owner(self, alert, owner): self.saved.append((alert, owner)); return True
    assignments, alerts = Assignments(), Alerts()
    event = {'event_type': 'alert', 'timestamp': '2026-01-01T00:01:00Z', 'src_ip': '10.8.0.2', 'dest_ip': '1.1.1.1',
             'alert': {'signature': 'TEST synthetic', 'severity': 2}}
    run = lambda trusted: ingest_personal_alert(json.dumps(event), assignments, alerts, evidence_trusted=trusted)
    assert not run(False) and alerts.saved == []
    assignments.values = [owner, owner]
    assert not run(True) and alerts.saved == []
    assignments.values = [owner]
    assert run(True) and alerts.saved[0][1] == owner
    event['dest_ip'] = '10.8.0.3'
    assert not run(True) and len(alerts.saved) == 1


def test_current_alert_requires_recent_event_stable_assignment_and_matching_snapshot():
    from datetime import timedelta
    from app.application.personal_alerts import ingest_current_alert
    from app.application.assignment_lifecycle import SnapshotPeer
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    owner = Assignment(IPv4Address('10.8.0.2'), 1, 'a'*32, now - timedelta(minutes=2))
    class Assignments:
        def find_at(self, address, timestamp): return [owner]
    class Alerts:
        def save_for_owner(self, alert, assigned): return assigned == owner
    event = {'event_type': 'alert', 'timestamp': now.isoformat(), 'src_ip': '10.8.0.2', 'dest_ip': '1.1.1.1',
             'alert': {'signature': 'Synthetic indicator', 'severity': 2}}
    peers = [SnapshotPeer(1, 'a'*32, '10.8.0.2')]
    def run(at, snapshot=peers):
        return ingest_current_alert(json.dumps(event), Assignments(), Alerts(), snapshot, at)
    assert run(now)
    assert run(now + timedelta(days=2))
    assert not run(now - timedelta(seconds=3))
    assert not run(now, [SnapshotPeer(2, 'b'*32, '10.8.0.2')])
    owner = Assignment(IPv4Address('10.8.0.2'), 1, 'a'*32, now - timedelta(seconds=30))
    assert not run(now)
