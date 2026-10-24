"""Read-only Linux security configuration and system hardening collectors."""

from pathlib import Path
from typing import Any, Dict, List, Optional

from app.schemas.os_evidence import OSEvidenceItemCreate, OSEvidenceStatus, OSPermissionState
from app.services.os_collectors.base import BaseOSCollector

# Standard allowlisted sysctl paths on Linux
ALLOWLISTED_SYSCTL_PATHS = {
    "randomize_va_space": "/proc/sys/kernel/randomize_va_space",
    "ip_forward": "/proc/sys/net/ipv4/ip_forward",
    "protected_symlinks": "/proc/sys/fs/protected_symlinks",
    "protected_hardlinks": "/proc/sys/fs/protected_hardlinks",
    "dmesg_restrict": "/proc/sys/kernel/dmesg_restrict",
    "kptr_restrict": "/proc/sys/kernel/kptr_restrict",
}


class LinuxKernelHardeningCollector(BaseOSCollector):
    """Read-only collector inspecting Linux kernel hardening sysctl parameters."""

    @property
    def name(self) -> str:
        return "linux_kernel_hardening_collector"

    @property
    def check_id(self) -> str:
        return "linux_kernel_hardening"

    @property
    def description(self) -> str:
        return "Reads allowlisted /proc/sys parameters to evaluate ASLR, IP forwarding, and link protection."

    @property
    def supported_os_families(self) -> List[str]:
        return ["linux"]

    def _read_sysctl_value(self, file_path: Path) -> Optional[int]:
        """Safely read a single integer value from a /proc/sys entry."""
        if not file_path.is_file():
            return None
        try:
            raw = file_path.read_text(encoding="utf-8", errors="replace").strip()
            return int(raw)
        except (ValueError, OSError):
            return None

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[OSEvidenceItemCreate]:
        """Collect kernel sysctl hardening values."""
        ctx = context or {}
        # Test override allows injecting a dictionary of mock sysctl values
        mock_values = ctx.get("mock_proc_sys")
        results: Dict[str, Any] = {}

        if mock_values is not None:
            results = mock_values
        else:
            for key_name, sysctl_path_str in ALLOWLISTED_SYSCTL_PATHS.items():
                val = self._read_sysctl_value(Path(sysctl_path_str))
                results[key_name] = val

        # Evaluate presence of core metrics
        aslr_val = results.get("randomize_va_space")
        ip_fwd_val = results.get("ip_forward")

        if aslr_val is None and ip_fwd_val is None and mock_values is None:
            return [
                OSEvidenceItemCreate(
                    collector_name=self.name,
                    check_id=self.check_id,
                    signal_name="kernel_sysctl_hardening",
                    observed_value=None,
                    structured_data={"read_attempted": list(ALLOWLISTED_SYSCTL_PATHS.keys())},
                    collection_status=OSEvidenceStatus.UNAVAILABLE,
                    permission_state=OSPermissionState.LIMITED,
                    explanatory_notes="Could not read Linux /proc/sys kernel parameters. Environment may not expose procfs.",
                )
            ]

        aslr_text = {
            2: "ASLR Fully Enabled (2)",
            1: "ASLR Conservative (1)",
            0: "ASLR Disabled (0)",
        }.get(aslr_val, f"ASLR Custom/Unknown ({aslr_val})")

        return [
            OSEvidenceItemCreate(
                collector_name=self.name,
                check_id=self.check_id,
                signal_name="kernel_sysctl_hardening",
                observed_value=f"{aslr_text}; IP Forwarding: {ip_fwd_val}",
                structured_data={
                    "randomize_va_space": aslr_val,
                    "ip_forward": ip_fwd_val,
                    "protected_symlinks": results.get("protected_symlinks"),
                    "protected_hardlinks": results.get("protected_hardlinks"),
                    "dmesg_restrict": results.get("dmesg_restrict"),
                    "kptr_restrict": results.get("kptr_restrict"),
                },
                collection_status=OSEvidenceStatus.OBSERVED,
                permission_state=OSPermissionState.GRANTED,
                explanatory_notes=(
                    f"Read kernel hardening parameters from /proc/sys: ASLR={aslr_val}, "
                    f"IP Forwarding={ip_fwd_val}."
                ),
            )
        ]


class LinuxSSHConfigCollector(BaseOSCollector):
    """Read-only collector inspecting /etc/ssh/sshd_config for hardening posture."""

    @property
    def name(self) -> str:
        return "linux_ssh_config_collector"

    @property
    def check_id(self) -> str:
        return "linux_ssh_hardening"

    @property
    def description(self) -> str:
        return "Inspects /etc/ssh/sshd_config to check root login and password authentication policy."

    @property
    def supported_os_families(self) -> List[str]:
        return ["linux"]

    def _parse_sshd_config(self, content: str) -> Dict[str, str]:
        """Parse directives from sshd_config text ignoring comments and case."""
        directives: Dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                key = parts[0].strip().lower()
                val = parts[1].strip()
                # In sshd_config, first occurrence takes precedence
                if key not in directives:
                    directives[key] = val
        return directives

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[OSEvidenceItemCreate]:
        """Collect SSH daemon hardening configuration."""
        ctx = context or {}
        config_path_str = ctx.get("sshd_config_path")
        path_obj = Path(config_path_str) if config_path_str else Path("/etc/ssh/sshd_config")

        if not path_obj.is_file():
            return [
                OSEvidenceItemCreate(
                    collector_name=self.name,
                    check_id=self.check_id,
                    signal_name="sshd_config_status",
                    observed_value=f"Config absent at '{path_obj}'",
                    structured_data={"file_path": str(path_obj)},
                    collection_status=OSEvidenceStatus.ABSENT,
                    permission_state=OSPermissionState.GRANTED,
                    explanatory_notes=(
                        f"SSH daemon configuration file was not found at '{path_obj}'. "
                        "OpenSSH server is likely not installed on this host."
                    ),
                )
            ]

        try:
            content = path_obj.read_text(encoding="utf-8", errors="replace")
        except PermissionError as exc:
            raise PermissionError(f"Permission denied reading '{path_obj}': {exc}") from exc

        directives = self._parse_sshd_config(content)
        root_login = directives.get("permitrootlogin", "prohibit-password (default)")
        password_auth = directives.get("passwordauthentication", "yes (default)")

        return [
            OSEvidenceItemCreate(
                collector_name=self.name,
                check_id=self.check_id,
                signal_name="sshd_hardening_configuration",
                observed_value=f"PermitRootLogin: {root_login}; PasswordAuthentication: {password_auth}",
                structured_data={
                    "file_path": str(path_obj),
                    "permit_root_login": root_login,
                    "password_authentication": password_auth,
                    "x11_forwarding": directives.get("x11forwarding"),
                    "max_auth_tries": directives.get("maxauthtries"),
                },
                collection_status=OSEvidenceStatus.OBSERVED,
                permission_state=OSPermissionState.GRANTED,
                explanatory_notes=f"Parsed SSH daemon directives from '{path_obj}'.",
            )
        ]


class LinuxPackageUpdateStatusCollector(BaseOSCollector):
    """Read-only collector inspecting local Ubuntu/Debian update notification metadata."""

    @property
    def name(self) -> str:
        return "linux_package_update_status_collector"

    @property
    def check_id(self) -> str:
        return "linux_package_update_status"

    @property
    def description(self) -> str:
        return "Reads locally cached update notification metadata (e.g. /var/lib/update-notifier/updates-available)."

    @property
    def supported_os_families(self) -> List[str]:
        return ["linux"]

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[OSEvidenceItemCreate]:
        """Collect local update notification status."""
        ctx = context or {}
        updates_file_str = ctx.get("updates_available_path")
        path_obj = (
            Path(updates_file_str)
            if updates_file_str
            else Path("/var/lib/update-notifier/updates-available")
        )

        if not path_obj.is_file():
            return [
                OSEvidenceItemCreate(
                    collector_name=self.name,
                    check_id=self.check_id,
                    signal_name="security_updates_cache",
                    observed_value=None,
                    structured_data={"file_path": str(path_obj)},
                    collection_status=OSEvidenceStatus.UNAVAILABLE,
                    permission_state=OSPermissionState.LIMITED,
                    explanatory_notes=(
                        f"Local update notification cache file '{path_obj}' is not available on this host. "
                        "The update-notifier package may not be active or has not generated a status file."
                    ),
                )
            ]

        try:
            content = path_obj.read_text(encoding="utf-8", errors="replace")
        except PermissionError as exc:
            raise PermissionError(f"Permission denied reading '{path_obj}': {exc}") from exc

        # Parse standard Ubuntu update notification banner
        total_updates: Optional[int] = None
        security_updates: Optional[int] = None

        for line in content.splitlines():
            line_clean = line.strip().lower()
            if "updates can be applied immediately" in line_clean or "updates can be installed immediately" in line_clean:
                tokens = line_clean.split()
                if tokens and tokens[0].isdigit():
                    total_updates = int(tokens[0])
            if "standard security updates" in line_clean or "security updates" in line_clean:
                tokens = line_clean.split()
                if tokens and tokens[0].isdigit():
                    security_updates = int(tokens[0])

        return [
            OSEvidenceItemCreate(
                collector_name=self.name,
                check_id=self.check_id,
                signal_name="security_updates_cache",
                observed_value=(
                    f"Available updates: {total_updates if total_updates is not None else 'unknown'}, "
                    f"Security updates: {security_updates if security_updates is not None else 'unknown'}"
                ),
                structured_data={
                    "file_path": str(path_obj),
                    "total_updates": total_updates,
                    "security_updates": security_updates,
                    "raw_banner": content.strip(),
                },
                collection_status=OSEvidenceStatus.OBSERVED,
                permission_state=OSPermissionState.GRANTED,
                explanatory_notes=f"Parsed local update notification metadata from '{path_obj}'.",
            )
        ]
