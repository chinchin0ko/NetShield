from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address

from app.application.attribution import Assignment, attribute_pre_nat_event


def test_attribution_requires_pre_nat_evidence_and_time_bounded_ownership():
    now = datetime(2026, 11, 20, tzinfo=timezone.utc)
    old = Assignment(IPv4Address('10.8.0.2'), 1, 'a' * 32, now, now + timedelta(hours=1))
    new = Assignment(IPv4Address('10.8.0.2'), 2, 'b' * 32, now + timedelta(hours=1))
    def find(time, assignments=(old, new), trusted=True, source='10.8.0.2', destination='1.1.1.1'):
        return attribute_pre_nat_event(source=source, destination=destination, occurred_at=time,
                                       assignments=list(assignments), trusted_pre_nat_sensor=trusted)
    assert find(now + timedelta(minutes=1)) == old
    assert find(now + timedelta(hours=1)) == new
    assert find(now - timedelta(seconds=1)) is None
    assert find(now + timedelta(minutes=1), trusted=False) is None
    assert find(now + timedelta(minutes=1), source='10.5.0.3') is None
    assert find(now + timedelta(minutes=1), source='1.1.1.1', destination='10.8.0.2') == old
    assert find(now + timedelta(minutes=1), destination='10.8.0.3') is None
    assert find(now.replace(tzinfo=None)) is None
    overlapping = Assignment(IPv4Address('10.8.0.2'), 3, 'c' * 32, now)
    assert find(now + timedelta(minutes=1), (old, overlapping)) is None
    missing_timezone = Assignment(IPv4Address('10.8.0.2'), 4, 'd' * 32, now.replace(tzinfo=None))
    assert find(now + timedelta(minutes=1), (missing_timezone,)) is None
