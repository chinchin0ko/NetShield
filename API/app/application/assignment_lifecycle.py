"""Fail-closed coordination of peer mutations and attribution history.

Only appropriate when *all* peer changes go through this coordinator and the
snapshot is taken atomically by the trusted controller. A failure leaves a gap
in attribution; it must never be backfilled from a later snapshot.
"""
from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address, ip_network
import re


@dataclass(frozen=True)
class SnapshotPeer:
    user_id: int
    device_id: str
    address: str


def validate_snapshot(peers):
    if not isinstance(peers, list):
        raise ValueError('invalid snapshot')
    addresses, devices = set(), set()
    for peer in peers:
        if not isinstance(peer, SnapshotPeer) or type(peer.user_id) is not int or peer.user_id <= 0:
            raise ValueError('invalid peer')
        if not re.fullmatch(r'[0-9a-f]{32}', peer.device_id):
            raise ValueError('invalid device')
        try:
            address = ip_address(peer.address)
        except (TypeError, ValueError):
            raise ValueError('invalid address') from None
        if not isinstance(address, IPv4Address) or address not in ip_network('10.8.0.0/24'):
            raise ValueError('invalid address')
        if address in addresses or (peer.user_id, peer.device_id) in devices:
            raise ValueError('ambiguous snapshot')
        addresses.add(address)
        devices.add((peer.user_id, peer.device_id))
    return peers


def mutate_with_history(store, controller, operation):
    """Close history before mutation; reopen only from an atomic verified snapshot.

    The store's exclusive lock must survive transactions, and suspend/open must
    each commit independently. The controller returns operation result and
    snapshot together under its peer-management lock. On exception, history
    remains closed and no identity may be inferred for the gap.
    """
    with store.exclusive():
        store.suspend()
        result, peers = controller.mutate_and_snapshot(operation)
        store.resume(validate_snapshot(peers))
        return result
