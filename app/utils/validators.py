import ipaddress
import re
from pathlib import Path


def is_valid_ip(target: str) -> bool:
    """Validate if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


def is_valid_subnet(target: str) -> bool:
    """Validate if the string is a valid CIDR network (e.g., 192.168.1.0/24)."""
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
        return network.is_private
    except ValueError:
        return False


def is_private_ip(target: str) -> bool:
    """Check if the target IP belongs to a private, loopback, or link-local range."""
    try:
        ip = ipaddress.ip_address(target.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def is_safe_target(target: str, allow_public: bool = False) -> tuple[bool, str]:
    """
    Ensure scan targets conform to defensive boundaries.
    By default, restricts scanning to private/internal networks or loopback.
    """
    cleaned = target.strip()
    if not cleaned:
        return False, "Target cannot be empty."

    # Check IP
    if is_valid_ip(cleaned):
        if not allow_public and not is_private_ip(cleaned):
            return (
                False,
                f"Target {cleaned} is a public IP address. AutoShield mandates explicit authorization and restricts external scanning by default.",
            )
        return True, "Valid target IP address."

    # Check CIDR
    if "/" in cleaned:
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
            if not allow_public and not net.is_private:
                return (
                    False,
                    "Subnet scanning is restricted to private RFC 1918 networks by default.",
                )
            if net.num_addresses > 256:
                return (
                    False,
                    f"Subnet /{net.prefixlen} contains {net.num_addresses} hosts. Max allowed for single scan is 256 (/24).",
                )
            return True, f"Valid private subnet with {net.num_addresses} addresses."
        except ValueError:
            return False, "Invalid CIDR notation."

    # Check Hostname / localhost
    if cleaned.lower() in ("localhost", "127.0.0.1", "::1"):
        return True, "Local loopback target."

    # Validate standard hostname syntax
    hostname_regex = re.compile(
        r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
    )
    if hostname_regex.match(cleaned):
        if not allow_public and not cleaned.endswith((".local", ".internal", ".lan", ".home")):
            return (
                False,
                "External domains require explicit public scanning authorization.",
            )
        return True, "Valid hostname."

    return False, "Target format not recognized as valid IP, subnet, or internal hostname."


def is_safe_filepath(base_directory: Path, user_path: str) -> tuple[bool, Path | None, str]:
    """Prevent directory traversal attacks."""
    try:
        resolved_base = base_directory.resolve()
        target_path = (base_directory / user_path).resolve()
        if not str(target_path).startswith(str(resolved_base)):
            return False, None, "Directory traversal detected."
        return True, target_path, "Safe path."
    except Exception as e:
        return False, None, f"Path resolution error: {e}"
