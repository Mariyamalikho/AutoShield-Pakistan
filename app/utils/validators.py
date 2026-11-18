import ipaddress


def is_valid_ip(target: str) -> bool:
    """Validate if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


def is_private_ip(target: str) -> bool:
    """Check if the target IP belongs to a private, loopback, or link-local range."""
    try:
        ip = ipaddress.ip_address(target.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False
