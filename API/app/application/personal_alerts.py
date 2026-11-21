"""Personal alert processing; not enabled for the post-NAT sensor.

The caller is responsible for establishing source identity, clock safety,
complete ownership and sensor continuity before setting evidence_trusted.
"""
from ipaddress import ip_address, IPv4Address
from app.application.alerts import parse_alert
from app.application.attribution import VPN_NETWORK, attribute_pre_nat_event


def ingest_personal_alert(line, assignments, alerts, *, evidence_trusted):
    alert = parse_alert(line)
    if alert is None or not evidence_trusted:
        return False
    try:
        addresses = {ip_address(alert.source_ip), ip_address(alert.destination_ip)}
    except (ValueError, TypeError):
        return False
    peers = [ip for ip in addresses if isinstance(ip, IPv4Address) and ip in VPN_NETWORK]
    if len(peers) != 1:
        return False
    history = assignments.find_at(peers[0], alert.occurred_at)
    owner = attribute_pre_nat_event(source=alert.source_ip, destination=alert.destination_ip,
                                   occurred_at=alert.occurred_at, assignments=history,
                                   trusted_pre_nat_sensor=True)
    if owner is None:
        return False
    return alerts.save_for_owner(alert, owner)


def ingest_current_alert(line, assignments, alerts, snapshot, database_now):
    """Accept delayed events only for a peer that is still uniquely assigned.

    The caller holds the same database session lock used by peer mutations.
    Timestamps near assignment changes are intentionally excluded.
    """
    return ingest_known_alert(parse_alert(line), assignments, alerts, snapshot, database_now)


def ingest_known_alert(alert, assignments, alerts, snapshot, database_now):
    """Apply the same ownership checks to both live and held events."""
    from datetime import timedelta
    if alert is None or database_now.tzinfo is None:
        return False
    age = database_now - alert.occurred_at
    if age < timedelta(seconds=-2):
        return False
    try:
        ips = {ip_address(alert.source_ip), ip_address(alert.destination_ip)}
    except (ValueError, TypeError):
        return False
    local = [ip for ip in ips if isinstance(ip, IPv4Address) and ip in VPN_NETWORK]
    if len(local) != 1:
        return False
    entries = assignments.find_at(local[0], alert.occurred_at)
    owner = attribute_pre_nat_event(source=alert.source_ip, destination=alert.destination_ip,
                                   occurred_at=alert.occurred_at, assignments=entries,
                                   trusted_pre_nat_sensor=True)
    if owner is None or owner.valid_until is not None or alert.occurred_at - owner.valid_from < timedelta(seconds=60):
        return False
    candidates = [p for p in snapshot if p.address == str(local[0])]
    if len(candidates) != 1 or candidates[0].user_id != owner.user_id or candidates[0].device_id != owner.device_id:
        return False
    return alerts.save_for_owner(alert, owner)
