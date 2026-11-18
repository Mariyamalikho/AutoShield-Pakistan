import os
import platform
import ctypes


def get_os_type() -> str:
    """Returns 'windows', 'linux', or 'darwin'."""
    return platform.system().lower()


def is_admin() -> bool:
    """Check if the application is running with administrative/root privileges."""
    try:
        if get_os_type() == "windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def get_system_metadata() -> dict:
    """Collect basic, safe system metadata without probing sensitive configs."""
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "hostname": platform.node(),
        "is_admin": is_admin(),
    }
