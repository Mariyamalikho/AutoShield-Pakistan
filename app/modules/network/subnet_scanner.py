"""
Authorized subnet host enumeration and concurrent port sweep.

Strictly enforces RFC 1918 private-address boundaries so the scanner
cannot be directed at public internet hosts.  Every candidate host is
independently validated by :func:`app.utils.validators.is_safe_target`
before a socket is opened.
"""
from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from app.modules.network.scanner import PortScanner, COMMON_PORTS
from app.utils.validators import is_safe_target

# ---------------------------------------------------------------------------
# Safety limits
# ---------------------------------------------------------------------------
_MAX_HOSTS = 256          # Hard ceiling on hosts per sweep
_DEFAULT_TIMEOUT = 0.8    # Tighter timeout for subnet sweeps
_DEFAULT_WORKERS = 20


def get_subnet_hosts(cidr: str) -> list[str]:
    """
    Return all usable host addresses in *cidr*.

    Parameters
    ----------
    cidr:
        A private IPv4 CIDR block, e.g. ``"192.168.1.0/24"``.

    Raises
    ------
    ValueError
        If the network is not an RFC 1918 private range, is invalid,
        or would enumerate more than :data:`_MAX_HOSTS` addresses.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR notation '{cidr}': {exc}") from exc

    if not network.is_private:
        raise ValueError(
            f"Subnet scanning is restricted to RFC 1918 private address space. "
            f"'{cidr}' resolves to a non-private network."
        )

    hosts = list(network.hosts())
    if len(hosts) > _MAX_HOSTS:
        raise ValueError(
            f"Subnet '{cidr}' contains {len(hosts)} host addresses, "
            f"which exceeds the maximum permitted sweep size of {_MAX_HOSTS}."
        )

    return [str(h) for h in hosts]


def scan_subnet(
    cidr: str,
    ports: Optional[list[int]] = None,
    timeout: float = _DEFAULT_TIMEOUT,
    max_workers: int = _DEFAULT_WORKERS,
) -> list[dict]:
    """
    Enumerate hosts in *cidr* and scan each for open *ports*.

    Each host is validated by :func:`~app.utils.validators.is_safe_target`
    before probing.  Hosts that fail validation are skipped and recorded
    with a ``skipped`` state.

    Parameters
    ----------
    cidr:
        RFC 1918 CIDR block to sweep.
    ports:
        Port list; defaults to :data:`~app.modules.network.scanner.COMMON_PORTS`.
    timeout:
        Per-port socket timeout.
    max_workers:
        Thread-pool concurrency cap.

    Returns
    -------
    list[dict]
        One entry per open port per reachable host, sorted by IP then port.

    Raises
    ------
    ValueError
        Propagated from :func:`get_subnet_hosts` for unsafe or oversized subnets.
    """
    host_list = get_subnet_hosts(cidr)        # raises ValueError if unsafe
    port_list = ports if ports is not None else list(COMMON_PORTS.keys())
    scanner = PortScanner(default_timeout=timeout, max_workers=max_workers)

    results: list[dict] = []

    def _scan_one(host: str) -> list[dict]:
        ok, reason = is_safe_target(host)
        if not ok:
            return [{
                "host": host,
                "port": None,
                "state": "skipped",
                "service": None,
                "response_time_ms": 0.0,
                "skip_reason": reason,
            }]
        open_ports = scanner.scan_host(
            host, ports=port_list, timeout=timeout, open_only=True
        )
        for entry in open_ports:
            entry["host"] = host
        return open_ports

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_scan_one, h): h for h in host_list}
            for future in as_completed(futures):
                try:
                    results.extend(future.result())
                except Exception:
                    pass
    except KeyboardInterrupt:
        # Return whatever has been collected so far
        pass

    # Sort by IP address numerically, then port
    def _sort_key(r: dict):
        host = r.get("host", "0.0.0.0")
        port = r.get("port") or 0
        try:
            return (int(ipaddress.ip_address(host)), port)
        except ValueError:
            return (0, port)

    results.sort(key=_sort_key)
    return results
