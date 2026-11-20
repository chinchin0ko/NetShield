"""Reference attribution rules; not connected to the global Suricata feed.

The caller must authenticate the sensor and supply a durable assignment history.
An IP address alone is not proof of ownership, especially after NAT or reuse.
"""
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, ip_address, ip_network

VPN_NETWORK = ip_network('10.8.0.0/24')


@dataclass(frozen=True)
class Assignment:
    address: IPv4Address
    user_id: int
    device_id: str
    valid_from: datetime
    valid_until: datetime | None = None


def attribute_pre_nat_event(*, source: str, destination: str, occurred_at: datetime,
                            assignments: list[Assignment], trusted_pre_nat_sensor: bool) -> Assignment | None:
    """Return an owner only for one unambiguous, time-valid VPN assignment.

    `trusted_pre_nat_sensor` must be established by the transport/service, not
    taken from event JSON. Never use this with host-side post-NAT events.
    """
    if not trusted_pre_nat_sensor or occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        return None
    try:
        addresses = {ip_address(source), ip_address(destination)}
    except (ValueError, TypeError):
        return None
    peers = {ip for ip in addresses if isinstance(ip, IPv4Address) and ip in VPN_NETWORK}
    # Two VPN clients in one event require per-side authorization, which is not implemented.
    if len(peers) != 1:
        return None
    matches = []
    for assignment in assignments:
        start, end = assignment.valid_from, assignment.valid_until
        if start.tzinfo is None or start.utcoffset() is None:
            return None
        if end is not None and (end.tzinfo is None or end.utcoffset() is None or end <= start):
            return None
        if assignment.address in peers and start <= occurred_at and (end is None or occurred_at < end):
            matches.append(assignment)
    # Fail closed on overlap, even if both entries claim the same user.
    return matches[0] if len(matches) == 1 else None
