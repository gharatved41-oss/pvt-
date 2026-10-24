"""Read-only Linux system inventory collectors for Debian and Ubuntu systems."""

from pathlib import Path
from typing import Any, Dict, List, Optional

from app.schemas.os_evidence import OSEvidenceItemCreate, OSEvidenceStatus, OSPermissionState
from app.services.os_collectors.base import BaseOSCollector
from app.utils.os_detect import parse_os_release_file


class LinuxOSReleaseCollector(BaseOSCollector):
    """Read-only collector inspecting /etc/os-release on Linux hosts."""

    @property
    def name(self) -> str:
        return "linux_os_release_collector"

    @property
    def check_id(self) -> str:
        return "linux_os_release"

    @property
    def description(self) -> str:
        return "Reads /etc/os-release to identify distribution, release codename, and version."

    @property
    def supported_os_families(self) -> List[str]:
        return ["linux"]

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[OSEvidenceItemCreate]:
        """Collect distribution metadata from /etc/os-release."""
        ctx = context or {}
        release_path = ctx.get("os_release_path")
        path_obj = Path(release_path) if release_path else Path("/etc/os-release")

        if not path_obj.exists():
            # Fallback to /usr/lib/os-release if default path doesn't exist
            fallback = Path("/usr/lib/os-release")
            if fallback.exists() and not release_path:
                path_obj = fallback
            else:
                raise FileNotFoundError(f"OS release file not found at '{path_obj}'")

        release_data = parse_os_release_file(path_obj)
        if not release_data:
            return [
                OSEvidenceItemCreate(
                    collector_name=self.name,
                    check_id=self.check_id,
                    signal_name="os_release_empty",
                    observed_value=None,
                    structured_data={"file_path": str(path_obj)},
                    collection_status=OSEvidenceStatus.ABSENT,
                    permission_state=OSPermissionState.GRANTED,
                    explanatory_notes=f"OS release file at '{path_obj}' contained no parseable configuration keys.",
                )
            ]

        os_name = release_data.get("PRETTY_NAME") or release_data.get("NAME") or "Linux"
        version_id = release_data.get("VERSION_ID") or ""
        codename = release_data.get("VERSION_CODENAME") or ""

        return [
            OSEvidenceItemCreate(
                collector_name=self.name,
                check_id=self.check_id,
                signal_name="os_release_info",
                observed_value=f"{os_name} ({version_id}) {codename}".strip(),
                structured_data={
                    "file_path": str(path_obj),
                    "distro_id": release_data.get("ID"),
                    "distro_name": os_name,
                    "version_id": version_id,
                    "codename": codename,
                    "id_like": release_data.get("ID_LIKE", "").split(),
                },
                collection_status=OSEvidenceStatus.OBSERVED,
                permission_state=OSPermissionState.GRANTED,
                explanatory_notes=f"Successfully read OS distribution identity from '{path_obj}'.",
            )
        ]


class LinuxDpkgStatusCollector(BaseOSCollector):
    """Read-only collector that directly parses the Debian / Ubuntu /var/lib/dpkg/status database.

    Operates completely in pure Python without executing any shell commands or subprocesses.
    """

    @property
    def name(self) -> str:
        return "linux_dpkg_collector"

    @property
    def check_id(self) -> str:
        return "linux_installed_packages"

    @property
    def description(self) -> str:
        return "Directly reads /var/lib/dpkg/status to enumerate installed software packages and versions."

    @property
    def supported_os_families(self) -> List[str]:
        return ["linux"]

    def _parse_dpkg_status(self, content: str) -> List[Dict[str, Any]]:
        """Parse the raw text of /var/lib/dpkg/status into structured package records.

        RFC 822 / Debian control file format:
        Paragraphs are separated by double newlines. Field continuations begin with whitespace.
        """
        packages: List[Dict[str, Any]] = []
        raw_paragraphs = content.split("\n\n")

        for paragraph in raw_paragraphs:
            if not paragraph.strip():
                continue

            pkg_dict: Dict[str, str] = {}
            current_field: Optional[str] = None

            for line in paragraph.splitlines():
                if not line:
                    continue

                # Continuation line
                if line.startswith((" ", "\t")):
                    if current_field:
                        # Append multiline text
                        pkg_dict[current_field] += " " + line.strip()
                    continue

                # Key-value header line
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip()
                    val = val.strip()
                    pkg_dict[key] = val
                    current_field = key
                else:
                    # Ignore malformed lines without colons
                    current_field = None

            # A valid package record must contain at least 'Package' and 'Version'
            pkg_name = pkg_dict.get("Package")
            pkg_version = pkg_dict.get("Version")
            if not pkg_name or not pkg_version:
                continue

            status_str = pkg_dict.get("Status", "")
            # Verify status: 'install ok installed' indicates actively installed package
            is_installed = "installed" in status_str.lower() and "deinstall" not in status_str.lower()

            if is_installed:
                packages.append({
                    "package": pkg_name,
                    "version": pkg_version,
                    "architecture": pkg_dict.get("Architecture", "unknown"),
                    "status": status_str,
                    "source": pkg_dict.get("Source", pkg_name),
                    "section": pkg_dict.get("Section", "unknown"),
                    "priority": pkg_dict.get("Priority", "unknown"),
                })

        return packages

    def collect(self, context: Optional[Dict[str, Any]] = None) -> List[OSEvidenceItemCreate]:
        """Collect package inventory from /var/lib/dpkg/status."""
        ctx = context or {}
        dpkg_path = ctx.get("dpkg_status_path")
        path_obj = Path(dpkg_path) if dpkg_path else Path("/var/lib/dpkg/status")

        if not path_obj.exists():
            raise FileNotFoundError(f"Debian status database not found at '{path_obj}'")

        try:
            content = path_obj.read_text(encoding="utf-8", errors="replace")
        except PermissionError as exc:
            raise PermissionError(f"Permission denied accessing '{path_obj}': {exc}") from exc

        packages = self._parse_dpkg_status(content)

        return [
            OSEvidenceItemCreate(
                collector_name=self.name,
                check_id=self.check_id,
                signal_name="installed_packages_manifest",
                observed_value=f"Total installed packages: {len(packages)}",
                structured_data={
                    "file_path": str(path_obj),
                    "package_count": len(packages),
                    "packages": packages,
                },
                collection_status=OSEvidenceStatus.OBSERVED,
                permission_state=OSPermissionState.GRANTED,
                explanatory_notes=(
                    f"Parsed {len(packages)} actively installed Debian/Ubuntu packages directly "
                    f"from '{path_obj}' using pure-Python read-only file parsing."
                ),
            )
        ]
