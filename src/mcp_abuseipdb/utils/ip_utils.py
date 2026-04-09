"""IP address classification helpers."""

from __future__ import annotations

import ipaddress
from typing import Union

IPv4Address = ipaddress.IPv4Address
IPv6Address = ipaddress.IPv6Address
IPv4Network = ipaddress.IPv4Network
IPv6Network = ipaddress.IPv6Network
IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]

_IPV4_PRIVATE_NETWORKS: tuple[IPv4Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
)

_IPV6_PRIVATE_NETWORKS: tuple[IPv6Network, ...] = (
    ipaddress.ip_network("fc00::/7"),  # unique local addresses
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("::1/128"),  # loopback
)


def is_private_ip(ip: IPAddress) -> bool:
    """Return True if *ip* should be treated as private/reserved."""
    if isinstance(ip, IPv4Address):
        return any(ip in network for network in _IPV4_PRIVATE_NETWORKS)
    return any(ip in network for network in _IPV6_PRIVATE_NETWORKS)


def is_private_network(network: IPNetwork) -> bool:
    """Return True if *network* is fully inside a private/reserved range."""
    if isinstance(network, IPv4Network):
        return any(network.subnet_of(private) for private in _IPV4_PRIVATE_NETWORKS)
    return any(network.subnet_of(private) for private in _IPV6_PRIVATE_NETWORKS)
