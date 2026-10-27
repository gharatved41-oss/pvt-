import json
import os
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from packaging import version as pkg_version

logger = logging.getLogger(__name__)

FIXTURE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures", "sample_cve_catalog.json")

def clean_version_str(v_str: str) -> str:
    """Normalize package version string for safe semantic comparison."""
    if not v_str:
        return "0.0.0"
    v_str = str(v_str).strip()
    # Remove debian epoch prefix like '1:8.9p1' -> '8.9p1'
    if ":" in v_str:
        v_str = v_str.split(":", 1)[1]
    # Remove distro and build tags (ubuntu, deb, el, fc, amzn, git)
    v_str = re.sub(r'(ubuntu|deb|el|fc|amzn|arch|build|\+git).*', '', v_str, flags=re.IGNORECASE)
    # Strip trailing patch letters like 9.3p1 -> 9.3.1
    v_str = re.sub(r'p(\d+)', r'.\1', v_str)
    # Convert debian hyphen revisions and tildes to dots so 0.105-32 becomes 0.105.32
    v_str = v_str.replace("-", ".").replace("~", ".")
    # Extract only valid version digits and dots
    match = re.search(r'(\d+(\.\d+)*)', v_str)
    if match:
        return match.group(1)
    return "0.0.0"

def is_version_vulnerable(installed: str, min_ver: str, max_ver: str) -> bool:
    """Compare version range strictly to prevent false positive matches."""
    try:
        norm_inst = clean_version_str(installed)
        norm_min = clean_version_str(min_ver)
        norm_max = clean_version_str(max_ver)
        
        parsed_inst = pkg_version.parse(norm_inst)
        parsed_min = pkg_version.parse(norm_min)
        parsed_max = pkg_version.parse(norm_max)
        
        return parsed_min <= parsed_inst <= parsed_max
    except Exception as e:
        logger.warning(f"Version comparison fallback for {installed}: {e}")
        # String fallback if non-standard
        return min_ver <= installed <= max_ver

class CVEService:
    def __init__(self):
        self.catalog = self._load_fixture_catalog()

    def _load_fixture_catalog(self) -> List[Dict[str, Any]]:
        if os.path.exists(FIXTURE_PATH):
            try:
                with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to read fixture catalog: {e}")
        return []

    def get_catalog_size(self) -> int:
        return len(self.catalog)

    def find_vulnerabilities(
        self,
        os_type: str,
        packages: List[Dict[str, Any]],
        configuration_metadata: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Evaluate packages and system configuration against known vulnerabilities.
        Deduplicates findings by CVE ID.
        """
        findings = []
        seen_cves = set()
        os_type_lower = os_type.lower()

        # 1. Package inventory matching
        for pkg in packages:
            pkg_name = pkg.get("name", "").strip().lower()
            pkg_ver = pkg.get("version", "").strip()

            for entry in self.catalog:
                target_component = entry.get("component", "").strip().lower()
                affected_platforms = [p.lower() for p in entry.get("affected_platforms", [])]

                # Strict check: platform must match and component name must match
                if os_type_lower in affected_platforms and target_component == pkg_name:
                    cve_id = entry["cve_id"]
                    if cve_id in seen_cves:
                        continue

                    min_ver = entry.get("min_version", "0.0.0")
                    max_ver = entry.get("max_version", "999.999.999")

                    if is_version_vulnerable(pkg_ver, min_ver, max_ver):
                        seen_cves.add(cve_id)
                        findings.append({
                            "cve_id": cve_id,
                            "title": entry["title"],
                            "affected_component": pkg_name,
                            "installed_version": pkg_ver,
                            "fixed_version": entry.get("fixed_version", "Vendor Patched"),
                            "cvss_v3_score": entry.get("cvss_v3_score", 7.0),
                            "cvss_v3_vector": entry.get("cvss_v3_vector", ""),
                            "severity": entry.get("severity", "medium"),
                            "description": entry.get("description", ""),
                            "references": entry.get("references", []),
                            "remediation": entry.get("remediation", {}),
                            "validation_procedure": entry.get("validation_procedure", {}),
                            "evidence": {
                                "evidence_type": "package_manifest",
                                "title": f"Package {pkg_name} installed version {pkg_ver}",
                                "raw_evidence": f"Package: {pkg_name}\nVersion: {pkg_ver}\nArch: {pkg.get('architecture', 'amd64')}\nStatus: {pkg.get('status', 'installed')}\nMatch Rule: {min_ver} <= {pkg_ver} <= {max_ver}"
                            }
                        })

        # 2. Insecure configuration heuristics (e.g. open ports, disabled firewall, selinux disabled)
        if configuration_metadata:
            if configuration_metadata.get("selinux_enforcing") is False and os_type_lower == "linux":
                cve_code = "SEC-CFG-LINUX-01"
                if cve_code not in seen_cves:
                    seen_cves.add(cve_code)
                    findings.append({
                        "cve_id": cve_code,
                        "title": "SELinux Security Enforcement Disabled",
                        "affected_component": "system-security-config",
                        "installed_version": "Permissive/Disabled",
                        "fixed_version": "Enforcing (SELINUX=enforcing)",
                        "cvss_v3_score": 6.5,
                        "cvss_v3_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                        "severity": "medium",
                        "description": "SELinux is in permissive or disabled state, eliminating mandatory access controls.",
                        "references": ["https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/using_selinux/"],
                        "remediation": {
                            "action_type": "config_hardening",
                            "title": "Enable SELinux Enforcing Mode",
                            "description": "Configure /etc/selinux/config to SELINUX=enforcing and relabel filesystem.",
                            "command_preview": "sudo setenforce 1 && sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
                            "expected_outcome": "SELinux mandatory access control active."
                        },
                        "validation_procedure": {
                            "procedure_code": "PROC-SEC-CFG-SELINUX",
                            "name": "SELinux Enforcement State Check",
                            "safety_level": "safe_non_destructive",
                            "preconditions": "Isolated Linux twin active.",
                            "description": "Executes getenforce command and inspects /sys/fs/selinux/enforce.",
                            "test_logic_type": "config_state_audit"
                        },
                        "evidence": {
                            "evidence_type": "config_directive",
                            "title": "SELinux status verified as disabled",
                            "raw_evidence": "selinux_enforcing: false in system configuration snapshot."
                        }
                    })

        return findings

cve_service = CVEService()
