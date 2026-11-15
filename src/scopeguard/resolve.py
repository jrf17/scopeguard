"""Name resolution used by DNS recon and connection pinning."""

from __future__ import annotations

import socket

from scopeguard.errors import NetworkError


def system_resolver(host: str, port: int) -> list[str]:
    """Resolve ``host`` and return unique addresses. Does not connect."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise NetworkError(f"dns resolution failed: {exc}", target=host) from exc
    found: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in found:
            found.append(address)
    return found
