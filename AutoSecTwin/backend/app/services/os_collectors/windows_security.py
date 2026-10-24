"""Read-only Windows security configuration collectors inspecting allowlisted registry keys."""

import sys
from typing import Any, Dict, List, Optional

from app.schemas.os_evidence import OSEvidenceItemCreate, OSEvidenceStatus, OSPermissionState
from app.services.os_collectors.base import BaseOSCollector


class WindowsDefenderStatusCollector(BaseOSCollector):
    r"""Read-only collector querying Windows Defender real-time protection policy keys."""

    @property
    def name(self) -> str:
        return "windows_defender_status_collector"

    @property
    def check_id(self) -> str:
        return "windows_defender_status"

    @property
    def description(self) -> str:
        return "Queries allowlisted Windows Defender registry keys to evaluate real-time protection state."

    @property
    def supported_os_families(self) -> List[str]:
        return ["windows"]

    def _query_live_defender_registry(self) -> Dict[str, Any]:
        """Safely read Windows Defender registry values."""
        import winreg

        results: Dict[str, Any] = {}

        # 1. Real-Time Protection subkey
        rtp_path = r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rtp_path, 0, winreg.KEY_READ) as key:
                for field in ("DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection"):
                    try:
                        val, _ = winreg.QueryValueEx(key, field)
                        results[field] = val
                    except FileNotFoundError:
                        pass
        except (PermissionError, FileNotFoundError, OSError):
            pass

        # 2. Base Windows Defender subkey
        base_path = r"SOFTWARE\Microsoft\Windows Defender"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path, 0, winreg.KEY_READ) as key:
                for field in ("DisableAntiSpyware", "DisableAntiVirus"):
                    try:
                        val, _ = winreg.QueryValueEx(key, field)
                        results[field] = val
                    except FileNotFoundError:
                        pass
        except (PermissionError, FileNotFoundError, OSError):
            pass

        return results

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[OSEvidenceItemCreate]:
        """Collect Windows Defender protection state."""
        ctx = context or {}
        mock_data = ctx.get("mock_defender_registry")
        data: Dict[str, Any] = {}

        if mock_data is not None:
            data = mock_data
        elif sys.platform == "win32":
            data = self._query_live_defender_registry()
        else:
            raise FileNotFoundError("Windows Defender registry is not accessible on non-Windows platforms.")

        # In modern Windows, if keys are absent, default is protection ENABLED (0) unless disabled by GPO
        # If Tamper Protection is active or keys cannot be queried, report state accordingly
        disable_rtp = data.get("DisableRealtimeMonitoring")
        disable_as = data.get("DisableAntiSpyware")

        is_rtp_active: Optional[bool] = None
        if disable_rtp is not None:
            is_rtp_active = disable_rtp == 0
        elif data:
            # If subkey exists but DisableRealtimeMonitoring is absent, default is Active (0)
            is_rtp_active = True

        status_text = "Unknown / Not Configured"
        if is_rtp_active is True:
            status_text = "Real-Time Protection Active"
        elif is_rtp_active is False:
            status_text = "Real-Time Protection Disabled"

        return [
            OSEvidenceItemCreate(
                collector_name=self.name,
                check_id=self.check_id,
                signal_name="windows_defender_realtime",
                observed_value=status_text,
                structured_data={
                    "realtime_monitoring_active": is_rtp_active,
                    "disable_realtime_monitoring": disable_rtp,
                    "disable_antispyware": disable_as,
                    "raw_registry_values": data,
                },
                collection_status=OSEvidenceStatus.OBSERVED if data else OSEvidenceStatus.UNAVAILABLE,
                permission_state=OSPermissionState.GRANTED,
                explanatory_notes=(
                    f"Queried Windows Defender registry status: {status_text}. "
                    "Note: In Windows 10/11 with Tamper Protection, policies default to enabled unless GPO overrides exist."
                ),
            )
        ]


class WindowsFirewallProfileCollector(BaseOSCollector):
    r"""Read-only collector querying Windows Firewall profiles across Standard, Domain, and Public."""

    @property
    def name(self) -> str:
        return "windows_firewall_profile_collector"

    @property
    def check_id(self) -> str:
        return "windows_firewall_status"

    @property
    def description(self) -> str:
        return "Queries Windows Firewall registry keys to verify active status on Domain, Standard, and Public profiles."

    @property
    def supported_os_families(self) -> List[str]:
        return ["windows"]

    def _query_live_firewall_registry(self) -> Dict[str, Any]:
        """Safely read Windows Firewall profile states."""
        import winreg

        profiles = {
            "domain_profile": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
            "standard_profile": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            "public_profile": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
        }
        results: Dict[str, Any] = {}

        for profile_name, subkey_path in profiles.items():
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_READ) as key:
                    try:
                        val, _ = winreg.QueryValueEx(key, "EnableFirewall")
                        results[profile_name] = {"enabled": val == 1, "raw_value": val}
                    except FileNotFoundError:
                        results[profile_name] = {"enabled": None, "raw_value": None}
            except (PermissionError, FileNotFoundError, OSError):
                results[profile_name] = {"enabled": None, "raw_value": None}

        return results

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[OSEvidenceItemCreate]:
        """Collect Windows Firewall profile statuses."""
        ctx = context or {}
        mock_data = ctx.get("mock_firewall_registry")
        data: Dict[str, Any] = {}

        if mock_data is not None:
            data = mock_data
        elif sys.platform == "win32":
            data = self._query_live_firewall_registry()
        else:
            raise FileNotFoundError("Windows Firewall registry is not available on non-Windows platforms.")

        domain_enabled = data.get("domain_profile", {}).get("enabled")
        standard_enabled = data.get("standard_profile", {}).get("enabled")
        public_enabled = data.get("public_profile", {}).get("enabled")

        summary_parts = []
        if domain_enabled is not None:
            summary_parts.append(f"Domain: {'ON' if domain_enabled else 'OFF'}")
        if standard_enabled is not None:
            summary_parts.append(f"Standard/Private: {'ON' if standard_enabled else 'OFF'}")
        if public_enabled is not None:
            summary_parts.append(f"Public: {'ON' if public_enabled else 'OFF'}")

        summary = ", ".join(summary_parts) if summary_parts else "Firewall profiles not readable"

        return [
            OSEvidenceItemCreate(
                collector_name=self.name,
                check_id=self.check_id,
                signal_name="windows_firewall_profiles",
                observed_value=summary,
                structured_data={
                    "domain_enabled": domain_enabled,
                    "standard_enabled": standard_enabled,
                    "public_enabled": public_enabled,
                    "details": data,
                },
                collection_status=OSEvidenceStatus.OBSERVED if summary_parts else OSEvidenceStatus.UNAVAILABLE,
                permission_state=OSPermissionState.GRANTED,
                explanatory_notes=f"Read Windows Firewall state across profiles: {summary}.",
            )
        ]


class WindowsSecuritySettingsCollector(BaseOSCollector):
    r"""Read-only collector querying User Account Control (UAC) and RDP Network Level Authentication (NLA)."""

    @property
    def name(self) -> str:
        return "windows_security_settings_collector"

    @property
    def check_id(self) -> str:
        return "windows_security_settings"

    @property
    def description(self) -> str:
        return "Queries allowlisted registry settings for UAC EnableLUA and RDP Network Level Authentication."

    @property
    def supported_os_families(self) -> List[str]:
        return ["windows"]

    def _query_live_security_settings(self) -> Dict[str, Any]:
        """Safely read UAC and RDP registry settings."""
        import winreg

        results: Dict[str, Any] = {}

        # 1. UAC Policies
        uac_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uac_path, 0, winreg.KEY_READ) as key:
                for field in ("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"):
                    try:
                        val, _ = winreg.QueryValueEx(key, field)
                        results[field] = val
                    except FileNotFoundError:
                        pass
        except (PermissionError, FileNotFoundError, OSError):
            pass

        # 2. RDP NLA
        rdp_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rdp_path, 0, winreg.KEY_READ) as key:
                try:
                    val, _ = winreg.QueryValueEx(key, "UserAuthentication")
                    results["rdp_nla_user_authentication"] = val
                except FileNotFoundError:
                    pass
        except (PermissionError, FileNotFoundError, OSError):
            pass

        return results

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[OSEvidenceItemCreate]:
        """Collect Windows UAC and RDP configuration settings."""
        ctx = context or {}
        mock_data = ctx.get("mock_security_settings_registry")
        data: Dict[str, Any] = {}

        if mock_data is not None:
            data = mock_data
        elif sys.platform == "win32":
            data = self._query_live_security_settings()
        else:
            raise FileNotFoundError("Windows registry is not accessible on non-Windows platforms.")

        enable_lua = data.get("EnableLUA")
        consent_prompt = data.get("ConsentPromptBehaviorAdmin")
        rdp_nla = data.get("rdp_nla_user_authentication")

        uac_status = "Unknown"
        if enable_lua == 1:
            uac_status = "Enabled"
        elif enable_lua == 0:
            uac_status = "Disabled"

        nla_status = "Unknown"
        if rdp_nla == 1:
            nla_status = "NLA Required"
        elif rdp_nla == 0:
            nla_status = "NLA Disabled"

        return [
            OSEvidenceItemCreate(
                collector_name=self.name,
                check_id=self.check_id,
                signal_name="windows_hardening_settings",
                observed_value=f"UAC: {uac_status}; RDP NLA: {nla_status}",
                structured_data={
                    "uac_enable_lua": enable_lua,
                    "uac_consent_prompt_behavior": consent_prompt,
                    "prompt_on_secure_desktop": data.get("PromptOnSecureDesktop"),
                    "rdp_nla_required": rdp_nla == 1 if rdp_nla is not None else None,
                    "raw_values": data,
                },
                collection_status=OSEvidenceStatus.OBSERVED if data else OSEvidenceStatus.UNAVAILABLE,
                permission_state=OSPermissionState.GRANTED,
                explanatory_notes=f"Read UAC (EnableLUA={enable_lua}) and RDP NLA setting ({nla_status}).",
            )
        ]
