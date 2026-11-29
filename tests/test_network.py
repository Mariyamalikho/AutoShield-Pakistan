"""
Tests for the Network Security Auditor module.

All socket I/O is mocked so the test suite never opens real network
connections or requires network access.
"""
from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from app.modules.network.scanner import PortScanner, COMMON_PORTS
from app.modules.network.banner import grab_banner
from app.modules.network.risk_mapper import classify_port_risk, SERVICE_RISK
from app.modules.network.subnet_scanner import get_subnet_hosts


# ---------------------------------------------------------------------------
# PortScanner — probe_port
# ---------------------------------------------------------------------------

class TestProbePort:
    """Unit tests for PortScanner.probe_port."""

    def setup_method(self):
        self.scanner = PortScanner(default_timeout=1.0)

    def test_probe_port_open(self):
        """connect_ex returning 0 should mark the port as open."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0

        with patch("app.modules.network.scanner.socket.socket", return_value=mock_sock):
            result = self.scanner.probe_port("127.0.0.1", 80)

        assert result["state"] == "open"
        assert result["port"] == 80
        assert result["service"] == "HTTP"

    def test_probe_port_closed(self):
        """connect_ex returning non-zero should mark the port as closed."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED

        with patch("app.modules.network.scanner.socket.socket", return_value=mock_sock):
            result = self.scanner.probe_port("127.0.0.1", 22)

        assert result["state"] == "closed"
        assert result["port"] == 22

    def test_probe_port_filtered_on_timeout(self):
        """A socket.timeout exception should return 'filtered' state."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout("timed out")

        with patch("app.modules.network.scanner.socket.socket", return_value=mock_sock):
            result = self.scanner.probe_port("192.168.1.1", 445)

        assert result["state"] == "filtered"

    def test_probe_port_connection_refused(self):
        """An explicit ConnectionRefusedError should return 'closed' state."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = ConnectionRefusedError()

        with patch("app.modules.network.scanner.socket.socket", return_value=mock_sock):
            result = self.scanner.probe_port("127.0.0.1", 3306)

        assert result["state"] == "closed"

    def test_probe_port_unknown_port_has_no_service(self):
        """A port not in COMMON_PORTS should have service=None."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0

        with patch("app.modules.network.scanner.socket.socket", return_value=mock_sock):
            result = self.scanner.probe_port("127.0.0.1", 9999)

        assert result["state"] == "open"
        assert result["service"] is None


# ---------------------------------------------------------------------------
# PortScanner — scan_host
# ---------------------------------------------------------------------------

class TestScanHost:
    """Integration-style tests for scan_host (sockets still mocked)."""

    def test_scan_host_returns_only_open_ports(self):
        """scan_host with open_only=True should omit closed/filtered ports."""
        scanner = PortScanner(default_timeout=0.5, max_workers=4)

        def fake_probe(host, port, timeout=None):
            # Simulate port 22 and 80 open, everything else closed
            if port in (22, 80):
                return {"port": port, "state": "open", "service": COMMON_PORTS.get(port), "response_time_ms": 1.0}
            return {"port": port, "state": "closed", "service": COMMON_PORTS.get(port), "response_time_ms": 0.5}

        with patch.object(scanner, "probe_port", side_effect=fake_probe):
            results = scanner.scan_host("127.0.0.1", ports=[22, 80, 443, 3389], open_only=True)

        assert len(results) == 2
        ports_found = {r["port"] for r in results}
        assert ports_found == {22, 80}

    def test_scan_host_sorted_by_port(self):
        """Results must be sorted ascending by port number."""
        scanner = PortScanner(default_timeout=0.5, max_workers=4)

        def fake_probe(host, port, timeout=None):
            return {"port": port, "state": "open", "service": None, "response_time_ms": 1.0}

        with patch.object(scanner, "probe_port", side_effect=fake_probe):
            results = scanner.scan_host("127.0.0.1", ports=[443, 22, 80], open_only=True)

        assert [r["port"] for r in results] == [22, 80, 443]


# ---------------------------------------------------------------------------
# Banner grabber
# ---------------------------------------------------------------------------

class TestGrabBanner:
    """Tests for the banner.grab_banner helper."""

    def test_grab_banner_non_eligible_port_returns_none(self):
        """Ports outside the banner-eligible set must return None immediately."""
        result = grab_banner("127.0.0.1", 3306)
        assert result is None

    def test_grab_banner_returns_first_line(self):
        """grab_banner should return the first sanitised line from the socket."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\nIgnored line\r\n"

        with patch("app.modules.network.banner.socket.socket", return_value=mock_sock):
            result = grab_banner("127.0.0.1", 22, timeout=1.0)

        assert result == "SSH-2.0-OpenSSH_8.9"

    def test_grab_banner_returns_none_on_timeout(self):
        """A socket timeout should silently return None."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("timed out")

        with patch("app.modules.network.banner.socket.socket", return_value=mock_sock):
            result = grab_banner("192.168.1.1", 21, timeout=0.1)

        assert result is None


# ---------------------------------------------------------------------------
# Risk mapper
# ---------------------------------------------------------------------------

class TestRiskMapper:
    """Tests for classify_port_risk."""

    def test_telnet_is_critical(self):
        """Port 23 (Telnet) must always classify as CRITICAL."""
        cls = classify_port_risk(23, "open")
        assert cls["severity"] == "CRITICAL"
        assert cls["risk_score"] >= 90

    def test_redis_is_critical(self):
        """Port 6379 (Redis) with no auth is a critical exposure."""
        cls = classify_port_risk(6379, "open")
        assert cls["severity"] == "CRITICAL"

    def test_ssh_is_low_risk(self):
        """Port 22 (SSH) should be LOW risk."""
        cls = classify_port_risk(22, "open")
        assert cls["severity"] == "LOW"

    def test_https_is_info(self):
        """Port 443 (HTTPS) should be INFO — it is expected."""
        cls = classify_port_risk(443, "open")
        assert cls["severity"] == "INFO"

    def test_closed_port_returns_zero_score(self):
        """A closed port should return INFO with risk_score 0."""
        cls = classify_port_risk(22, "closed")
        assert cls["severity"] == "INFO"
        assert cls["risk_score"] == 0

    def test_unknown_port_gets_medium_default(self):
        """A port not in SERVICE_RISK catalogue defaults to MEDIUM."""
        cls = classify_port_risk(54321, "open")
        assert cls["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Subnet scanner — get_subnet_hosts
# ---------------------------------------------------------------------------

class TestGetSubnetHosts:
    """Tests for subnet host enumeration (no socket calls needed)."""

    def test_valid_private_cidr_returns_host_list(self):
        hosts = get_subnet_hosts("192.168.1.0/30")
        # /30 has 2 usable hosts: .1 and .2
        assert "192.168.1.1" in hosts
        assert "192.168.1.2" in hosts
        assert len(hosts) == 2

    def test_public_cidr_raises_value_error(self):
        with pytest.raises(ValueError, match="RFC 1918"):
            get_subnet_hosts("8.8.8.0/24")

    def test_oversized_subnet_raises_value_error(self):
        # /23 has 510 hosts — exceeds MAX_HOSTS=256
        with pytest.raises(ValueError, match="exceeds"):
            get_subnet_hosts("192.168.0.0/23")

    def test_invalid_cidr_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid CIDR"):
            get_subnet_hosts("not-a-cidr")


# ---------------------------------------------------------------------------
# Network routes
# ---------------------------------------------------------------------------

class TestNetworkRoutes:
    """Smoke tests for the /network blueprint via Flask test client."""

    def test_network_index_requires_login(self, client):
        """Unauthenticated requests should redirect to login."""
        response = client.get("/network/")
        assert response.status_code in (301, 302)

    def test_network_index_accessible_when_logged_in(self, auth_client):
        """Authenticated users should reach the network scanner page."""
        response = auth_client.get("/network/")
        assert response.status_code == 200
        assert b"Network Security Auditor" in response.data

    def test_network_scan_post_blocked_without_auth_checkbox(self, auth_client):
        """Submitting without the authorised checkbox must flash an error."""
        response = auth_client.post(
            "/network/scan",
            data={"scan_mode": "host", "target": "127.0.0.1", "timeout": "1.0"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"authorised" in response.data.lower()

    def test_network_scan_blocks_public_ip(self, auth_client):
        """Scanning a public IP must be blocked and flash an error."""
        response = auth_client.post(
            "/network/scan",
            data={
                "scan_mode": "host",
                "target": "8.8.8.8",
                "timeout": "1.0",
                "authorised": "1",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        # Expect a danger flash about blocked scan
        assert b"block" in response.data.lower() or b"public" in response.data.lower()
