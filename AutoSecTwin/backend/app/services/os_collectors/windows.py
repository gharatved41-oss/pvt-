"""Read-only Windows system inventory collectors inspecting explicitly allowlisted registry keys."""

import sys
from typing import Any, Dict, List, Optional

from app.schemas.os_evidence import OSEvidenceItemCreate, OSEvidenceStatus, OSPermissionState
from app.services.os_collectors.base import BaseOSCollector

# Allowlisted Windows Registry paths for installed software enumeration
UNINSTALL_REG_PATHS = [
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM_64"),
    (r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM_32"),
    (r"Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU"),
]


class WindowsOSIdentityCollector(BaseOSCollector):
    r"""Read-only collector querying Windows NT\CurrentVersion build and UBR metadata."""

    @property
    def name(self) -> str:
        return "windows_os_identity_collector"

    @property
    def check_id(self) -> str:
        return "windows_build_info"

    @property
    def description(self) -> str:
        return "Queries Windows NT CurrentVersion registry key for release, build, and UBR patch level."

    @property
    def supported_os_families(self) -> List[str]:
        return ["windows"]

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[OSEvidenceItemCreate]:
        """Collect Windows OS build identity."""
        ctx = context or {}
        mock_reader = ctx.get("winreg_identity_reader")
        data: Dict[str, Any] = {}

        if mock_reader is not None:
            # Test override
            data = mock_reader()
        elif sys.platform == "win32":
            try:
                import winreg  # Isolated Windows import

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
                            data[field] = val
                        except FileNotFoundError:
                            pass
            except PermissionError as exc:
                raise PermissionError(f"Registry access denied reading Windows NT CurrentVersion: {exc}") from exc
            except Exception as exc:
                raise RuntimeError(f"Failed querying Windows NT CurrentVersion registry: {exc}") from exc
        else:
            raise FileNotFoundError("Windows registry is not available on this operating system.")

        if not data:
            return [
                OSEvidenceItemCreate(
                    collector_name=self.name,
                    check_id=self.check_id,
                    signal_name="windows_build_info",
                    observed_value=None,
                    structured_data={},
                    collection_status=OSEvidenceStatus.ABSENT,
                    permission_state=OSPermissionState.GRANTED,
                    explanatory_notes="Registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion contained no readable fields.",
                )
            ]

        prod_name = data.get("ProductName", "Windows")
        display_ver = data.get("DisplayVersion") or data.get("ReleaseId") or "unknown"
        build_num = data.get("CurrentBuild") or data.get("CurrentBuildNumber") or "unknown"
        ubr = data.get("UBR")

        # Windows 11 build adjustments (build >= 22000 is Windows 11)
        try:
            build_int = int(str(build_num))
            if build_int >= 22000 and "10" in prod_name:
                prod_name = prod_name.replace("10", "11")
        except ValueError:
            pass

        full_build = f"{build_num}.{ubr}" if ubr is not None else str(build_num)

        return [
            OSEvidenceItemCreate(
                collector_name=self.name,
                check_id=self.check_id,
                signal_name="windows_build_info",
                observed_value=f"{prod_name} {display_ver} (Build {full_build})",
                structured_data={
                    "product_name": prod_name,
                    "display_version": display_ver,
                    "build_number": str(build_num),
                    "ubr": ubr,
                    "full_build": full_build,
                    "edition_id": data.get("EditionID"),
                },
                collection_status=OSEvidenceStatus.OBSERVED,
                permission_state=OSPermissionState.GRANTED,
                explanatory_notes=f"Retrieved Windows version {display_ver} build {full_build} via read-only registry query.",
            )
        ]


class WindowsInstalledSoftwareCollector(BaseOSCollector):
    """Read-only collector scanning explicitly allowlisted Windows Uninstall registry hives."""

    @property
    def name(self) -> str:
        return "windows_installed_software_collector"

    @property
    def check_id(self) -> str:
        return "windows_software_inventory"

    @property
    def description(self) -> str:
        return "Reads allowlisted Uninstall registry keys across HKLM and HKCU to catalog installed applications."

    @property
    def supported_os_families(self) -> List[str]:
        return ["windows"]

    def _read_live_registry_software(self) -> List[Dict[str, Any]]:
        """Safely enumerate software entries from live Windows registry hives."""
        import winreg

        apps: List[Dict[str, Any]] = []
        hives = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM_64"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM_32"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU"),
        ]

        for root_key, subkey_path, hive_label in hives:
            try:
                with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_READ) as uninstall_key:
                    num_subkeys, _, _ = winreg.QueryInfoKey(uninstall_key)
                    for i in range(num_subkeys):
                        try:
                            subkey_name = winreg.EnumKey(uninstall_key, i)
                            with winreg.OpenKey(uninstall_key, subkey_name, 0, winreg.KEY_READ) as app_key:
                                app_dict: Dict[str, Any] = {"hive": hive_label, "key_name": subkey_name}
                                for val_name in ("DisplayName", "DisplayVersion", "Publisher", "InstallDate", "SystemComponent"):
                                    try:
                                        val, _ = winreg.QueryValueEx(app_key, val_name)
                                        app_dict[val_name] = val
                                    except FileNotFoundError:
                                        pass

                                # Filter: Skip entries without DisplayName or marked as internal SystemComponent
                                if not app_dict.get("DisplayName"):
                                    continue
                                if app_dict.get("SystemComponent") == 1:
                                    continue

                                apps.append(app_dict)
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
            except (PermissionError, FileNotFoundError, OSError):
                # If an individual hive is inaccessible, continue scanning remaining hives
                continue

        return apps

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[OSEvidenceItemCreate]:
        """Collect installed software from Windows registry."""
        ctx = context or {}
        mock_software = ctx.get("mock_software_registry")
        raw_apps: List[Dict[str, Any]] = []

        if mock_software is not None:
            raw_apps = mock_software
        elif sys.platform == "win32":
            raw_apps = self._read_live_registry_software()
        else:
            raise FileNotFoundError("Windows registry is not available on non-Windows platforms.")

        # Deduplicate applications by (DisplayName, DisplayVersion)
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for app in raw_apps:
            display_name = str(app.get("DisplayName", "")).strip()
            # Filter: Skip entries without DisplayName or marked as internal SystemComponent
            if not display_name:
                continue
            if app.get("SystemComponent") == 1:
                continue

            display_version = str(app.get("DisplayVersion", "")).strip() or "unspecified"
            publisher = str(app.get("Publisher", "")).strip() or "unspecified"
            install_date = str(app.get("InstallDate", "")).strip() or None

            dedup_key = (display_name.lower(), display_version.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            deduped.append({
                "name": display_name,
                "version": display_version,
                "publisher": publisher,
                "install_date": install_date,
                "hive": app.get("hive", "unknown"),
            })

        return [
            OSEvidenceItemCreate(
                collector_name=self.name,
                check_id=self.check_id,
                signal_name="installed_software_manifest",
                observed_value=f"Total installed applications: {len(deduped)}",
                structured_data={
                    "application_count": len(deduped),
                    "applications": deduped,
                },
                collection_status=OSEvidenceStatus.OBSERVED,
                permission_state=OSPermissionState.GRANTED,
                explanatory_notes=(
                    f"Enumerated {len(deduped)} installed applications from allowlisted Windows Uninstall "
                    "registry keys using non-destructive, read-only queries."
                ),
            )
        ]
