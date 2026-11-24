"""
Lightweight service banner grabber for administrative network ports.

Attempts to read the initial greeting bytes that many services emit
immediately after a TCP connection is established.  Results are used
by the risk classifier to refine findings — not to perform any
active probing or exploitation.
"""
from __future__ import annotations

import socket
import re
from typing import Optional

# Ports where most services send an unsolicited greeting banner
_BANNER_PORTS: frozenset[int] = frozenset({21, 22, 25, 80, 110, 143})

# Minimal probes to trigger a response on request/response protocols
_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
}

_MAX_BANNER_BYTES = 1024
_SAFE_ENCODING = "utf-8"


def grab_banner(
    host: str,
    port: int,
    timeout: float = 2.0,
) -> Optional[str]:
    """
    Attempt to read a service greeting from *host*:*port*.

    Only ports in the well-known banner set are attempted; all others
    return ``None`` immediately to avoid unexpected side-effects.

    Parameters
    ----------
    host:
        Target IPv4 address or hostname.
    port:
        TCP port number.
    timeout:
        Socket timeout in seconds.

    Returns
    -------
    str | None
        First line of the banner with control characters stripped,
        or ``None`` if the port is not banner-eligible, the connection
        is refused, or the service does not emit a greeting.
    """
    if port not in _BANNER_PORTS:
        return None

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))

        # Some protocols require a minimal request before they respond
        probe = _PROBES.get(port)
        if probe:
            sock.sendall(probe)

        raw = sock.recv(_MAX_BANNER_BYTES)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        sock.close()

    if not raw:
        return None

    try:
        text = raw.decode(_SAFE_ENCODING, errors="replace")
    except Exception:
        return None

    # Return only the first meaningful line; strip control characters
    first_line = text.splitlines()[0] if text.splitlines() else text
    return _sanitise(first_line)


def _sanitise(value: str) -> str:
    """Remove non-printable characters and trim whitespace."""
    cleaned = re.sub(r"[^\x20-\x7E]", "", value)
    return cleaned.strip()[:256]
