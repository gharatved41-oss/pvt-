"""Safe, non-destructive host operating system and architecture detection utility."""

import hashlib
import os
import platform
import sys
from pathlib import Path
from typing import Any, Dict, Optional


def get_anonymized_host_identifier(salt: str = "vulntwin_v1") -> str:
    """Generate a privacy-preserving SHA-256 hash identifying the host machine.

    Avoids exposing raw MAC addresses, hardware serial numbers, or full machine GUIDs.
    """
    node_name = platform.node() or "unknown_host"
    system_name = platform.system() or "unknown_sys"
    raw = f"{salt}:{system_name}:{node_name}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def detect_os_family() -> str:
    """Identify the high-level operating system family.

    Returns:
        'windows', 'linux', 'darwin', or 'unknown'
    """
    sys_plat = sys.platform.lower()
    if sys_plat.startswith("win"):
        return "windows"
    if sys_plat.startswith("linux"):
        return "linux"
    if sys_plat.startswith("darwin"):
        return "darwin"
    return "unknown"


def parse_os_release_file(file_path: Path) -> Dict[str, str]:
    """Parse standard freedesktop /etc/os-release format into a dictionary.

    Args:
        file_path: Path to os-release file.

    Returns:
        Dictionary of key-value pairs stripped of shell quoting.
    """
    if not file_path.is_file():
        return {}

    data: Dict[str, str] = {}
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                data[key] = val
    except Exception:
        # Read errors handled gracefully without bubbling up
        pass
    return data


def detect_os_info(
    os_release_override: Optional[Path] = None,
    proc_version_override: Optional[Path] = None,
    winreg_reader: Optional[Any] = None,
) -> Dict[str, Any]:
    """Detect local host operating system details using read-only sources.

    Args:
        os_release_override: Optional path to mock /etc/os-release (for testing).
        proc_version_override: Optional path to mock /proc/version (for testing).
        winreg_reader: Optional callable or dict returning Windows registry values (for testing).

    Returns:
        Structured dictionary with normalized OS metadata.
    """
    family = detect_os_family()
    arch = platform.machine() or "x86_64"
    hostname = platform.node() or "localhost"
    host_id = get_anonymized_host_identifier()

    info: Dict[str, Any] = {
        "os_family": family,
        "os_name": platform.system(),
        "os_version": platform.release(),
        "os_build": platform.version(),
        "architecture": arch,
        "hostname": hostname,
        "host_identifier": host_id,
        "is_supported": False,
        "details": {},
    }

    # -------------------------------------------------------------
    # 1. Linux (Ubuntu / Debian / Generic)
    # -------------------------------------------------------------
    if family == "linux" or os_release_override is not None:
        release_path = os_release_override or Path("/etc/os-release")
        if not release_path.is_file() and os_release_override is None:
            # Fallback path on older distributions
            release_path = Path("/usr/lib/os-release")

        os_release_data = parse_os_release_file(release_path)
        if os_release_data:
            info["os_name"] = os_release_data.get("PRETTY_NAME") or os_release_data.get("NAME") or "Linux"
            info["os_version"] = os_release_data.get("VERSION_ID") or os_release_data.get("VERSION") or platform.release()
            info["os_family"] = "linux"
            distro_id = (os_release_data.get("ID") or "").lower()
            distro_like = (os_release_data.get("ID_LIKE") or "").lower().split()
            # We explicitly support Ubuntu and Debian first
            is_supported = distro_id in ("ubuntu", "debian") or any(d in ("ubuntu", "debian") for d in distro_like)
            info["is_supported"] = is_supported
            info["details"] = {
                "distro_id": distro_id,
                "version_codename": os_release_data.get("VERSION_CODENAME") or "",
                "id_like": distro_like,
            }

        # Check kernel version via /proc/version if available
        proc_path = proc_version_override or Path("/proc/version")
        if proc_path.is_file():
            try:
                proc_ver = proc_path.read_text(encoding="utf-8", errors="replace").strip()
                info["os_build"] = proc_ver.split()[2] if len(proc_ver.split()) >= 3 else platform.release()
                info["details"]["kernel_banner"] = proc_ver
            except Exception:
                info["os_build"] = platform.release()
        else:
            info["os_build"] = platform.release()

        return info

    # -------------------------------------------------------------
    # 2. Windows 10 / 11
    # -------------------------------------------------------------
    if family == "windows" or winreg_reader is not None:
        info["os_family"] = "windows"
        win_details: Dict[str, Any] = {}

        # Allow test injection of mock registry reader
        if winreg_reader is not None:
            win_details = winreg_reader()
        elif sys.platform == "win32":
            try:
                import winreg  # Isolated Windows-only import

                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                    0,
                    winreg.KEY_READ,
                ) as key:
                    for field in (
                        "ProductName",
                        "DisplayVersion",
                        "CurrentBuild",
                        "CurrentBuildNumber",
                        "UBR",
                        "EditionID",
                        "ReleaseId",
                    ):
                        try:
                            val, _ = winreg.QueryValueEx(key, field)
                            win_details[field] = val
                        except FileNotFoundError:
                            pass
            except Exception as exc:
                win_details["query_error"] = str(exc)

        if win_details:
            prod_name = win_details.get("ProductName", "Windows")
            display_ver = win_details.get("DisplayVersion") or win_details.get("ReleaseId") or platform.release()
            build_num = win_details.get("CurrentBuild") or win_details.get("CurrentBuildNumber") or platform.version()
            ubr = win_details.get("UBR")

            # In Windows 11, ProductName often still says Windows 10 Enterprise/Pro, build >= 22000 is Windows 11
            try:
                build_int = int(str(build_num))
                if build_int >= 22000 and "10" in prod_name:
                    prod_name = prod_name.replace("10", "11")
                is_supported_win = build_int >= 19041  # Windows 10 2004+ and Windows 11
            except ValueError:
                is_supported_win = True

            full_build = f"{build_num}.{ubr}" if ubr is not None else str(build_num)
            info["os_name"] = prod_name
            info["os_version"] = display_ver
            info["os_build"] = full_build
            info["is_supported"] = is_supported_win
            info["details"] = win_details
        else:
            # Fallback to standard platform library
            info["os_name"] = f"Windows {platform.release()}"
            info["is_supported"] = platform.release() in ("10", "11")

        return info

    # Other / Unsupported
    info["is_supported"] = False
    return info
