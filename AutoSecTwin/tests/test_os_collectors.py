"""Automated unit and isolation tests for Milestone 2: Read-Only OS Detection & System Inventory Collectors."""

from pathlib import Path
from typing import Any, Dict, List, Optional
import pytest

from app.schemas.os_evidence import OSEvidenceStatus, OSPermissionState
from app.services.os_collectors.base import BaseOSCollector
from app.services.os_collectors.linux import (
    LinuxDpkgStatusCollector,
    LinuxOSReleaseCollector,
)
from app.services.os_collectors.manager import OSCollectorManager
from app.services.os_collectors.windows import (
    WindowsInstalledSoftwareCollector,
    WindowsOSIdentityCollector,
)
from app.utils.os_detect import (
    detect_os_family,
    detect_os_info,
    get_anonymized_host_identifier,
    parse_os_release_file,
)


# =====================================================================
# 1. OS Detection Utility Tests
# =====================================================================

def test_detect_os_family_returns_valid_string() -> None:
    """Verify that detect_os_family returns a known platform family."""
    family = detect_os_family()
    assert family in ("windows", "linux", "darwin", "unknown")


def test_get_anonymized_host_identifier() -> None:
    """Verify that host identifier generates a consistent 64-character SHA-256 hash."""
    h1 = get_anonymized_host_identifier("vulntwin_test")
    h2 = get_anonymized_host_identifier("vulntwin_test")
    assert len(h1) == 64
    assert h1 == h2
    assert int(h1, 16) > 0


def test_parse_os_release_file_valid_format(tmp_path: Path) -> None:
    """Verify parsing of standard /etc/os-release lines with quotes and whitespace."""
    content = """
    NAME="Ubuntu"
    VERSION="22.04.4 LTS (Jammy Jellyfish)"
    ID=ubuntu
    ID_LIKE=debian
    PRETTY_NAME="Ubuntu 22.04.4 LTS"
    VERSION_ID="22.04"
    VERSION_CODENAME=jammy
    # Comment line
    UBUNTU_CODENAME=jammy
    """
    release_file = tmp_path / "os-release"
    release_file.write_text(content, encoding="utf-8")

    data = parse_os_release_file(release_file)
    assert data["ID"] == "ubuntu"
    assert data["VERSION_ID"] == "22.04"
    assert data["VERSION_CODENAME"] == "jammy"
    assert data["PRETTY_NAME"] == "Ubuntu 22.04.4 LTS"


def test_detect_os_info_linux_mock(tmp_path: Path) -> None:
    """Verify detect_os_info identifies mock Ubuntu installation."""
    release_content = (
        'NAME="Ubuntu"\n'
        'VERSION_ID="22.04"\n'
        'ID=ubuntu\n'
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
        'VERSION_CODENAME=jammy\n'
    )
    release_file = tmp_path / "os-release"
    release_file.write_text(release_content, encoding="utf-8")

    proc_ver_file = tmp_path / "version"
    proc_ver_file.write_text(
        "Linux version 6.5.0-28-generic (buildd@lcy02-amd64-001) (gcc version 11.4.0) #29~22.04.1-Ubuntu\n",
        encoding="utf-8",
    )

    info = detect_os_info(
        os_release_override=release_file,
        proc_version_override=proc_ver_file,
    )

    assert info["os_family"] == "linux"
    assert info["os_name"] == "Ubuntu 22.04.4 LTS"
    assert info["os_version"] == "22.04"
    assert info["os_build"] == "6.5.0-28-generic"
    assert info["is_supported"] is True
    assert info["details"]["distro_id"] == "ubuntu"
    assert info["details"]["version_codename"] == "jammy"


def test_detect_os_info_windows_mock() -> None:
    """Verify detect_os_info identifies mock Windows 11 build via injected registry reader."""
    def mock_winreg() -> Dict[str, Any]:
        return {
            "ProductName": "Windows 10 Pro",  # Windows 11 often still reports Windows 10 in ProductName
            "DisplayVersion": "23H2",
            "CurrentBuild": "22631",
            "UBR": 3447,
            "EditionID": "Professional",
        }

    info = detect_os_info(winreg_reader=mock_winreg)

    assert info["os_family"] == "windows"
    assert "Windows 11" in info["os_name"]
    assert info["os_version"] == "23H2"
    assert info["os_build"] == "22631.3447"
    assert info["is_supported"] is True


# =====================================================================
# 2. Linux Read-Only Collectors Tests
# =====================================================================

def test_linux_os_release_collector_success(tmp_path: Path) -> None:
    """Verify LinuxOSReleaseCollector emits valid structured evidence."""
    release_file = tmp_path / "os-release"
    release_file.write_text(
        'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian\nVERSION_CODENAME=bookworm\n',
        encoding="utf-8",
    )

    collector = LinuxOSReleaseCollector()
    results = collector.collect(context={"os_release_path": str(release_file)})

    assert len(results) == 1
    ev = results[0]
    assert ev.collector_name == "linux_os_release_collector"
    assert ev.check_id == "linux_os_release"
    assert ev.collection_status == OSEvidenceStatus.OBSERVED
    assert ev.permission_state == OSPermissionState.GRANTED
    assert "Debian" in str(ev.observed_value)
    assert ev.structured_data["distro_id"] == "debian"
    assert ev.structured_data["codename"] == "bookworm"


def test_linux_os_release_collector_missing_file_raises() -> None:
    """Verify LinuxOSReleaseCollector raises FileNotFoundError when target file does not exist."""
    collector = LinuxOSReleaseCollector()
    with pytest.raises(FileNotFoundError):
        collector.collect(context={"os_release_path": "/nonexistent/path/os-release"})


SAMPLE_DPKG_STATUS = """
Package: libc6
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 13024
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 2.35-0ubuntu3.1
Source: glibc
Description: GNU C Library: Shared libraries
 Contains standard libraries used by nearly all programs.
 Extended description continuation line.

Package: openssl
Status: install ok installed
Priority: optional
Section: utils
Architecture: amd64
Version: 3.0.2-0ubuntu1.10
Description: Secure Sockets Layer toolkit - cryptographic utility

Package: removed-tool
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0.0
Description: Tool that was uninstalled but configs remain

# Malformed line without colon
MalformedBlockWithoutPackageKey: 123
"""


def test_linux_dpkg_status_collector_parsing(tmp_path: Path) -> None:
    """Verify parsing of /var/lib/dpkg/status into clean package manifest."""
    dpkg_file = tmp_path / "dpkg-status"
    dpkg_file.write_text(SAMPLE_DPKG_STATUS, encoding="utf-8")

    collector = LinuxDpkgStatusCollector()
    results = collector.collect(context={"dpkg_status_path": str(dpkg_file)})

    assert len(results) == 1
    ev = results[0]
    assert ev.collector_name == "linux_dpkg_collector"
    assert ev.check_id == "linux_installed_packages"
    assert ev.collection_status == OSEvidenceStatus.OBSERVED
    assert ev.permission_state == OSPermissionState.GRANTED

    packages = ev.structured_data["packages"]
    # Only installed packages (libc6 and openssl) should be included; removed-tool is filtered out
    assert len(packages) == 2

    pkg_map = {p["package"]: p for p in packages}
    assert "libc6" in pkg_map
    assert pkg_map["libc6"]["version"] == "2.35-0ubuntu3.1"
    assert pkg_map["libc6"]["architecture"] == "amd64"
    assert pkg_map["libc6"]["source"] == "glibc"

    assert "openssl" in pkg_map
    assert pkg_map["openssl"]["version"] == "3.0.2-0ubuntu1.10"


def test_linux_dpkg_status_collector_malformed_and_empty(tmp_path: Path) -> None:
    """Verify collector handles completely empty or garbage files gracefully."""
    empty_file = tmp_path / "empty-status"
    empty_file.write_text("random garbage without any package block\n", encoding="utf-8")

    collector = LinuxDpkgStatusCollector()
    results = collector.collect(context={"dpkg_status_path": str(empty_file)})

    assert len(results) == 1
    assert results[0].structured_data["package_count"] == 0
    assert results[0].structured_data["packages"] == []


# =====================================================================
# 3. Windows Read-Only Collectors Tests
# =====================================================================

def test_windows_os_identity_collector_mock() -> None:
    """Verify WindowsOSIdentityCollector parses Windows 11 build and UBR via mock reader."""
    def mock_reader() -> Dict[str, Any]:
        return {
            "ProductName": "Windows 11 Pro",
            "DisplayVersion": "23H2",
            "CurrentBuild": "22631",
            "UBR": 3447,
            "EditionID": "Professional",
        }

    collector = WindowsOSIdentityCollector()
    results = collector.collect(context={"winreg_identity_reader": mock_reader})

    assert len(results) == 1
    ev = results[0]
    assert ev.collector_name == "windows_os_identity_collector"
    assert ev.check_id == "windows_build_info"
    assert ev.collection_status == OSEvidenceStatus.OBSERVED
    assert "22631.3447" in str(ev.observed_value)
    assert ev.structured_data["build_number"] == "22631"
    assert ev.structured_data["ubr"] == 3447


MOCK_WINDOWS_SOFTWARE_HIVE = [
    {
        "DisplayName": "Python 3.12.2 (64-bit)",
        "DisplayVersion": "3.12.2150.0",
        "Publisher": "Python Software Foundation",
        "InstallDate": "20240315",
        "hive": "HKLM_64",
    },
    {
        "DisplayName": "Git version 2.44.0",
        "DisplayVersion": "2.44.0",
        "Publisher": "The Git Development Community",
        "hive": "HKLM_64",
    },
    # Duplicate entry in Wow6432Node
    {
        "DisplayName": "Git version 2.44.0",
        "DisplayVersion": "2.44.0",
        "Publisher": "The Git Development Community",
        "hive": "HKLM_32",
    },
    # Internal system component to exclude
    {
        "DisplayName": "Microsoft Visual C++ 2022 X84 Additional Runtime",
        "DisplayVersion": "14.38.33130",
        "SystemComponent": 1,
        "hive": "HKLM_64",
    },
    # Entry without DisplayName
    {
        "DisplayVersion": "1.0.0",
        "hive": "HKCU",
    },
]


def test_windows_installed_software_collector_deduplication() -> None:
    """Verify software enumeration deduplicates identical entries and excludes system components."""
    collector = WindowsInstalledSoftwareCollector()
    results = collector.collect(context={"mock_software_registry": MOCK_WINDOWS_SOFTWARE_HIVE})

    assert len(results) == 1
    ev = results[0]
    assert ev.collector_name == "windows_installed_software_collector"
    assert ev.check_id == "windows_software_inventory"
    assert ev.collection_status == OSEvidenceStatus.OBSERVED

    apps = ev.structured_data["applications"]
    # Python and Git only (duplicate Git removed, system component removed, missing name removed)
    assert len(apps) == 2

    app_names = {a["name"]: a for a in apps}
    assert "Python 3.12.2 (64-bit)" in app_names
    assert app_names["Python 3.12.2 (64-bit)"]["version"] == "3.12.2150.0"
    assert "Git version 2.44.0" in app_names


# =====================================================================
# 4. Collector Manager and Error Containment Tests
# =====================================================================

class FailingCollector(BaseOSCollector):
    """Test collector simulating permission denied."""

    @property
    def name(self) -> str:
        return "failing_collector"

    @property
    def check_id(self) -> str:
        return "permission_test"

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[Any]:
        raise PermissionError("Access is denied to security hive")


class CrashingCollector(BaseOSCollector):
    """Test collector simulating unexpected runtime exception."""

    @property
    def name(self) -> str:
        return "crashing_collector"

    @property
    def check_id(self) -> str:
        return "crash_test"

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[Any]:
        raise RuntimeError("Simulated unhandled collector defect")


def test_os_collector_manager_filters_by_platform() -> None:
    """Verify manager skips collectors unsupported on the target OS family with NOT_CHECKED status."""
    manager = OSCollectorManager()
    manager.register(LinuxOSReleaseCollector())
    manager.register(WindowsOSIdentityCollector())

    # Run for Linux target OS: Windows collector should emit not_checked
    results_linux = manager.run_all(os_family="linux", context={"os_release_path": "/nonexistent"})
    stat_map = {r.collector_name: r.collection_status for r in results_linux}
    assert stat_map["windows_os_identity_collector"] == OSEvidenceStatus.NOT_CHECKED

    # Run for Windows target OS: Linux collector should emit not_checked
    results_win = manager.run_all(os_family="windows", context={"winreg_identity_reader": lambda: {}})
    stat_map_win = {r.collector_name: r.collection_status for r in results_win}
    assert stat_map_win["linux_os_release_collector"] == OSEvidenceStatus.NOT_CHECKED


def test_os_collector_manager_permission_error_containment() -> None:
    """Verify that PermissionError is safely captured as UNAVAILABLE with DENIED state."""
    manager = OSCollectorManager()
    manager.register(FailingCollector())

    results = manager.run_all(os_family="linux")
    assert len(results) == 1
    ev = results[0]
    assert ev.collection_status == OSEvidenceStatus.UNAVAILABLE
    assert ev.permission_state == OSPermissionState.DENIED
    assert "PermissionError" in ev.structured_data["error_type"]
    assert "Audit limitation" in str(ev.explanatory_notes)


def test_os_collector_manager_unexpected_crash_containment() -> None:
    """Verify that unexpected exceptions are caught and recorded as ERROR without crashing."""
    manager = OSCollectorManager()
    manager.register(CrashingCollector())

    results = manager.run_all(os_family="linux")
    assert len(results) == 1
    ev = results[0]
    assert ev.collection_status == OSEvidenceStatus.ERROR
    assert ev.structured_data["error_type"] == "RuntimeError"
    assert "Simulated unhandled collector defect" in ev.structured_data["error_message"]
