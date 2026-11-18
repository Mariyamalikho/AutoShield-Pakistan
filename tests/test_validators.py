from app.utils.validators import (
    is_valid_ip,
    is_valid_subnet,
    is_private_ip,
    is_safe_target,
    is_safe_filepath,
)
from pathlib import Path


def test_ip_validation():
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("10.0.0.1") is True
    assert is_valid_ip("127.0.0.1") is True
    assert is_valid_ip("::1") is True
    assert is_valid_ip("999.999.999.999") is False
    assert is_valid_ip("not_an_ip") is False


def test_subnet_validation():
    assert is_valid_subnet("192.168.1.0/24") is True
    assert is_valid_subnet("10.0.0.0/16") is True
    assert is_valid_subnet("8.8.8.0/24") is False  # Public IP network
    assert is_valid_subnet("invalid/cidr") is False


def test_private_ip_check():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False


def test_safe_target_boundaries():
    # Private IP allowed by default
    safe, msg = is_safe_target("192.168.1.10")
    assert safe is True

    # Public IP blocked by default
    safe, msg = is_safe_target("142.250.190.46")
    assert safe is False
    assert "public IP" in msg

    # Localhost allowed
    safe, msg = is_safe_target("localhost")
    assert safe is True

    # Large subnet blocked
    safe, msg = is_safe_target("10.0.0.0/8")
    assert safe is False


def test_safe_filepath_directory_traversal():
    base = Path("H:/AutoShield-Pakistan/rules").resolve()
    
    # Safe path inside base
    safe, resolved, msg = is_safe_filepath(base, "suspicious_files.yar")
    assert safe is True
    assert str(resolved).startswith(str(base))

    # Dangerous path traversing outside base
    safe, resolved, msg = is_safe_filepath(base, "../../Windows/System32/cmd.exe")
    assert safe is False
    assert "traversal" in msg.lower()
