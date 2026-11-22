"""
TCP port scanner using non-blocking socket connect probes.

Supports single-host probing and concurrent host scanning against a
configurable port list. All target addresses are validated by the shared
validator layer before any socket is opened.
"""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ---------------------------------------------------------------------------
# Well-known port catalogue
# ---------------------------------------------------------------------------
COMMON_PORTS: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
}


class PortScanner:
    """Non-blocking TCP connect scanner with configurable timeouts."""

    # Ports that commonly return banners on first connection
    BANNER_ELIGIBLE = {21, 22, 25, 80, 110, 143}

    def __init__(self, default_timeout: float = 1.0, max_workers: int = 20) -> None:
        self.default_timeout = default_timeout
        self.max_workers = max_workers

    # ------------------------------------------------------------------
    # Low-level probe
    # ------------------------------------------------------------------
    def probe_port(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
    ) -> dict:
        """
        Attempt a TCP connect to *host*:*port*.

        Returns a dict::

            {
                "port": int,
                "state": "open" | "closed" | "filtered",
                "service": str | None,
                "response_time_ms": float,
            }

        ``"filtered"`` is returned for socket-level errors that indicate the
        packet was dropped rather than actively refused (e.g. ETIMEDOUT,
        EHOSTUNREACH).
        """
        t = timeout if timeout is not None else self.default_timeout
        service = COMMON_PORTS.get(port)
        result: dict = {
            "port": port,
            "state": "filtered",
            "service": service,
            "response_time_ms": 0.0,
        }

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(t)
        t_start = time.monotonic()
        try:
            ret = sock.connect_ex((host, port))
            elapsed = (time.monotonic() - t_start) * 1000
            result["response_time_ms"] = round(elapsed, 2)
            if ret == 0:
                result["state"] = "open"
            else:
                result["state"] = "closed"
        except ConnectionRefusedError:
            elapsed = (time.monotonic() - t_start) * 1000
            result["response_time_ms"] = round(elapsed, 2)
            result["state"] = "closed"
        except socket.timeout:
            elapsed = (time.monotonic() - t_start) * 1000
            result["response_time_ms"] = round(elapsed, 2)
            result["state"] = "filtered"
        except OSError:
            # Covers EHOSTUNREACH, ENETUNREACH, permission errors, etc.
            elapsed = (time.monotonic() - t_start) * 1000
            result["response_time_ms"] = round(elapsed, 2)
            result["state"] = "filtered"
        finally:
            sock.close()

        return result

    # ------------------------------------------------------------------
    # Host-level scan
    # ------------------------------------------------------------------
    def scan_host(
        self,
        host: str,
        ports: Optional[list[int]] = None,
        timeout: Optional[float] = None,
        max_workers: Optional[int] = None,
        open_only: bool = True,
    ) -> list[dict]:
        """
        Scan *host* across *ports* concurrently.

        Parameters
        ----------
        host:
            Resolved or raw IPv4 address / hostname to scan.
        ports:
            List of TCP port numbers. Defaults to :data:`COMMON_PORTS`.
        timeout:
            Per-port socket timeout in seconds.
        max_workers:
            Thread-pool concurrency cap.
        open_only:
            When ``True`` (default) only open ports are returned.

        Returns
        -------
        list[dict]
            Sorted ascending by port number.
        """
        if ports is None:
            ports = list(COMMON_PORTS.keys())
        workers = max_workers if max_workers is not None else self.max_workers
        t = timeout if timeout is not None else self.default_timeout

        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self.probe_port, host, p, t): p for p in ports
            }
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if not open_only or res["state"] == "open":
                        results.append(res)
                except Exception:
                    # Swallow individual probe failures; the port stays absent.
                    pass

        results.sort(key=lambda r: r["port"])
        return results
