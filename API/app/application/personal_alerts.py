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
