"""
Service-aware risk classification for open TCP ports.

Risk levels are determined by the protocol's inherent security posture,
not merely by whether a port is open.  An open SSH port on a patched
system is low risk; Telnet anywhere is critical regardless of context.

Risk scores map to the five-tier severity scale used across the platform:
  CRITICAL  → 90–100
  HIGH      → 70–89
  MEDIUM    → 40–69
  LOW       → 10–39
  INFO      → 0–9
"""
from __future__ import annotations

from typing import Optional

# ---------------------------------------------------------------------------
# Static risk catalogue keyed by port number
# ---------------------------------------------------------------------------
SERVICE_RISK: dict[int, dict] = {
    21: {
        "severity": "HIGH",
        "risk_score": 75,
        "explanation": (
            "FTP transmits credentials and data in cleartext. "
            "Passive and active mode both expose session content to network observers."
        ),
        "remediation_hint": (
            "Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS with explicit TLS. "
            "Restrict FTP access to trusted IP ranges if migration is not immediately possible."
        ),
    },
    22: {
        "severity": "LOW",
        "risk_score": 15,
        "explanation": (
            "SSH provides encrypted remote administration. "
            "Risk is low when key-based authentication is enforced and password login is disabled."
        ),
        "remediation_hint": (
            "Disable password authentication in sshd_config. "
            "Restrict access with AllowUsers or firewall rules. "
            "Keep the SSH daemon updated to receive security patches."
        ),
    },
    23: {
        "severity": "CRITICAL",
        "risk_score": 95,
        "explanation": (
            "Telnet sends all traffic — including credentials — in plaintext. "
            "Network observers can trivially capture usernames, passwords, and session data."
        ),
        "remediation_hint": (
            "Disable the Telnet service immediately and migrate all remote administration to SSH. "
            "Block port 23 at the perimeter firewall."
        ),
    },
    25: {
        "severity": "MEDIUM",
        "risk_score": 50,
        "explanation": (
            "SMTP open to the internet without authentication controls may be exploited "
            "as an open relay, enabling spam distribution and IP reputation damage."
        ),
        "remediation_hint": (
            "Require SMTP AUTH for all outbound mail. "
            "Enable STARTTLS. "
            "Restrict relay permissions to known sender IP ranges."
        ),
    },
    53: {
        "severity": "MEDIUM",
        "risk_score": 40,
        "explanation": (
            "An open DNS resolver can be abused for amplification-based DDoS attacks "
            "and may expose internal zone information if zone transfers are unrestricted."
        ),
        "remediation_hint": (
            "Restrict recursive queries to authorized client subnets only. "
            "Disable zone transfers to untrusted hosts. "
            "Enable DNSSEC for zones you manage."
        ),
    },
    80: {
        "severity": "LOW",
        "risk_score": 20,
        "explanation": (
            "HTTP serves content without transport encryption. "
            "Credentials and session tokens submitted over HTTP are visible to network observers."
        ),
        "remediation_hint": (
            "Redirect all HTTP traffic to HTTPS with a permanent (301) redirect. "
            "Enable HSTS with an appropriate max-age directive."
        ),
    },
    110: {
        "severity": "HIGH",
        "risk_score": 70,
        "explanation": (
            "POP3 without TLS transmits email content and login credentials in cleartext."
        ),
        "remediation_hint": (
            "Migrate to POP3S (port 995) or IMAPS (port 993). "
            "Disable plaintext POP3 at the mail server configuration level."
        ),
    },
    139: {
        "severity": "HIGH",
        "risk_score": 80,
        "explanation": (
            "NetBIOS over TCP/IP exposes Windows workgroup/domain information "
            "and may allow unauthenticated session enumeration on older hosts."
        ),
        "remediation_hint": (
            "Disable NetBIOS over TCP/IP via network adapter settings unless required for legacy compatibility. "
            "Block port 139 at the perimeter firewall."
        ),
    },
    143: {
        "severity": "HIGH",
        "risk_score": 70,
        "explanation": (
            "Plaintext IMAP exposes email content and credentials over the network."
        ),
        "remediation_hint": (
            "Enable STARTTLS or migrate clients to IMAPS on port 993. "
            "Reject plaintext authentication at the mail server."
        ),
    },
    443: {
        "severity": "INFO",
        "risk_score": 5,
        "explanation": (
            "HTTPS with TLS provides encrypted web communication. "
            "This port being open is expected for web services."
        ),
        "remediation_hint": (
            "Ensure TLS certificates are valid and renewed before expiry. "
            "Disable deprecated TLS 1.0 and 1.1 in the web server configuration."
        ),
    },
    445: {
        "severity": "CRITICAL",
        "risk_score": 92,
        "explanation": (
            "SMB exposed to the network has historically been the vector for high-impact "
            "ransomware campaigns (e.g., WannaCry, NotPetya). "
            "Unauthenticated or weakly authenticated SMB access permits lateral movement."
        ),
        "remediation_hint": (
            "Block port 445 at the perimeter firewall immediately. "
            "Apply all available OS security patches. "
            "Require SMB signing. "
            "Disable SMBv1 on all hosts."
        ),
    },
    3306: {
        "severity": "HIGH",
        "risk_score": 80,
        "explanation": (
            "A MySQL instance reachable over the network without strict access controls "
            "increases the attack surface significantly. "
            "Direct database exposure bypasses application-layer security."
        ),
        "remediation_hint": (
            "Bind MySQL to 127.0.0.1 unless remote access is explicitly required. "
            "Restrict remote user grants to specific source IPs. "
            "Enable TLS for client connections."
        ),
    },
    3389: {
        "severity": "HIGH",
        "risk_score": 85,
        "explanation": (
            "RDP exposed to the internet is a primary target for brute-force attacks "
            "and has been the entry point for numerous ransomware incidents."
        ),
        "remediation_hint": (
            "Place RDP behind a VPN — do not expose port 3389 directly to the internet. "
            "Enable Network Level Authentication. "
            "Apply all Windows security patches promptly."
        ),
    },
    5432: {
        "severity": "HIGH",
        "risk_score": 78,
        "explanation": (
            "PostgreSQL reachable on the network exposes the database engine to "
            "unauthorised access attempts if host-based authentication is misconfigured."
        ),
        "remediation_hint": (
            "Review pg_hba.conf and restrict access to application server IPs only. "
            "Enable SSL for all client connections. "
            "Do not use the superuser role for application queries."
        ),
    },
    6379: {
        "severity": "CRITICAL",
        "risk_score": 90,
        "explanation": (
            "Redis has no authentication by default in many configurations. "
            "An exposed Redis instance can be used to read cached data, "
            "overwrite application state, or achieve remote code execution via config manipulation."
        ),
        "remediation_hint": (
            "Bind Redis to 127.0.0.1 and block port 6379 at the firewall. "
            "Set a strong requirepass in redis.conf. "
            "Disable dangerous commands (FLUSHALL, CONFIG, DEBUG) in production."
        ),
    },
    8080: {
        "severity": "LOW",
        "risk_score": 25,
        "explanation": (
            "Port 8080 is commonly used for development or proxy HTTP services. "
            "Unintended exposure of a development server may leak application internals."
        ),
        "remediation_hint": (
            "Confirm whether this service is intentional. "
            "Development servers should not be accessible on production networks. "
            "Redirect or restrict access if the service is not required externally."
        ),
    },
}

# Default for ports not in the catalogue
_UNKNOWN_RISK: dict = {
    "severity": "MEDIUM",
    "risk_score": 45,
    "explanation": "An open port was detected on a non-standard service. Manual review is recommended.",
    "remediation_hint": (
        "Identify the process listening on this port with 'ss -tlnp' (Linux) or "
        "'netstat -ano' (Windows). Close or firewall the port if the service is unnecessary."
    ),
}


def classify_port_risk(
    port: int,
    state: str,
    banner: Optional[str] = None,
) -> dict:
    """
    Return a risk classification dict for an open *port*.

    Parameters
    ----------
    port:
        TCP port number.
    state:
        Port state string (``"open"``, ``"closed"``, ``"filtered"``).
        Only ``"open"`` ports receive a meaningful risk score.
    banner:
        Optional service banner string captured by :mod:`banner`.
        May downgrade SSH risk if banner indicates a modern OpenSSH version.

    Returns
    -------
    dict
        ``{severity, risk_score, explanation, remediation_hint}``
    """
    if state != "open":
        return {
            "severity": "INFO",
            "risk_score": 0,
            "explanation": f"Port {port} is {state}.",
            "remediation_hint": "",
        }

    base = SERVICE_RISK.get(port, _UNKNOWN_RISK).copy()

    # Contextual refinement: SSH with modern banner is genuinely low risk
    if port == 22 and banner:
        if "OpenSSH" in banner:
            base["explanation"] += f"  Banner: {banner!r}."

    # Telnet banner confirms active service — escalate explanation
    if port == 23 and banner:
        base["explanation"] += (
            f"  Active Telnet service confirmed by banner: {banner!r}."
        )

    return base
