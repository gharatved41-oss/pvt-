"""Evaluates collected OS security configuration evidence into structured findings.

Enforces strict separation of severity, confidence, and exploitability.
Exploitability is strictly UNKNOWN for configuration checks.
Missing or unavailable evidence is NEVER treated as a PASS or proof of safety.
"""

from typing import List

from app.schemas.os_evidence import OSEvidenceItemCreate, OSEvidenceStatus
from app.schemas.os_finding import (
    OSConfidence,
    OSExploitability,
    OSFindingCreate,
    OSFindingType,
    OSSeverity,
)


def evaluate_security_configuration_evidence(
    evidence_items: List[OSEvidenceItemCreate],
) -> List[OSFindingCreate]:
    """Evaluate raw evidence observations and produce structured misconfiguration findings.

    Args:
        evidence_items: Collection of observed evidence items from registered probes.

    Returns:
        List of OSFindingCreate objects for confirmed misconfigurations.
    """
    findings: List[OSFindingCreate] = []

    for item in evidence_items:
        # Crucial safety rule: Skip unavailable, absent, or errored evidence
        # Missing evidence is NOT proof of security and never produces a PASS
        if item.collection_status != OSEvidenceStatus.OBSERVED or not item.structured_data:
            continue

        data = item.structured_data

        # -------------------------------------------------------------
        # 1. Linux Kernel Hardening (ASLR & IP Forwarding)
        # -------------------------------------------------------------
        if item.check_id == "linux_kernel_hardening":
            aslr = data.get("randomize_va_space")
            if aslr == 0:
                findings.append(
                    OSFindingCreate(
                        finding_type=OSFindingType.MISCONFIGURATION,
                        advisory_id="CONFIG-LINUX-ASLR-OFF",
                        title="Address Space Layout Randomization (ASLR) Disabled in Kernel",
                        component_name="kernel.randomize_va_space",
                        installed_version="0",
                        fixed_version="2",
                        severity=OSSeverity.HIGH,
                        confidence=OSConfidence.HIGH,
                        exploitability=OSExploitability.UNKNOWN,
                        advisory_source="cis_benchmark_linux",
                        match_basis="sysctl_procfs_direct_read",
                        description=(
                            "ASLR is disabled (randomize_va_space=0). Memory addresses for stack, heap, and "
                            "shared libraries are predictable, significantly simplifying binary exploitation."
                        ),
                    )
                )
            elif aslr == 1:
                findings.append(
                    OSFindingCreate(
                        finding_type=OSFindingType.MISCONFIGURATION,
                        advisory_id="CONFIG-LINUX-ASLR-CONSERVATIVE",
                        title="Address Space Layout Randomization (ASLR) Incompletely Enabled (Conservative)",
                        component_name="kernel.randomize_va_space",
                        installed_version="1",
                        fixed_version="2",
                        severity=OSSeverity.MEDIUM,
                        confidence=OSConfidence.HIGH,
                        exploitability=OSExploitability.UNKNOWN,
                        advisory_source="cis_benchmark_linux",
                        match_basis="sysctl_procfs_direct_read",
                        description=(
                            "ASLR is set to conservative mode (1). The brk data segment is not randomized, "
                            "leaving heap addresses predictable."
                        ),
                    )
                )

            ip_fwd = data.get("ip_forward")
            if ip_fwd == 1:
                findings.append(
                    OSFindingCreate(
                        finding_type=OSFindingType.MISCONFIGURATION,
                        advisory_id="CONFIG-LINUX-IP-FORWARD",
                        title="IPv4 Packet Forwarding Enabled on Non-Router Host",
                        component_name="net.ipv4.ip_forward",
                        installed_version="1",
                        fixed_version="0",
                        severity=OSSeverity.LOW,
                        confidence=OSConfidence.HIGH,
                        exploitability=OSExploitability.UNKNOWN,
                        advisory_source="cis_benchmark_linux",
                        match_basis="sysctl_procfs_direct_read",
                        description=(
                            "IPv4 forwarding is enabled (ip_forward=1). Unless this host is a dedicated network "
                            "router or container gateway, packet routing between interfaces should be disabled."
                        ),
                    )
                )

        # -------------------------------------------------------------
        # 2. Linux SSH Server Hardening
        # -------------------------------------------------------------
        elif item.check_id == "linux_ssh_hardening":
            root_login = str(data.get("permit_root_login", "")).lower()
            if root_login in ("yes", "without-password"):
                findings.append(
                    OSFindingCreate(
                        finding_type=OSFindingType.MISCONFIGURATION,
                        advisory_id="CONFIG-SSH-ROOT-LOGIN",
                        title="SSH Daemon Configured to Permit Direct Root Logins",
                        component_name="sshd_config:PermitRootLogin",
                        installed_version=root_login,
                        fixed_version="no",
                        severity=OSSeverity.HIGH,
                        confidence=OSConfidence.HIGH,
                        exploitability=OSExploitability.UNKNOWN,
                        advisory_source="cis_benchmark_linux",
                        match_basis="sshd_config_direct_parse",
                        description=(
                            f"The SSH server configuration explicitly allows direct root authentication ('{root_login}'). "
                            "Administrative access should require logging in as an unprivileged user followed by sudo elevation."
                        ),
                    )
                )

        # -------------------------------------------------------------
        # 3. Windows UAC Policies & RDP NLA
        # -------------------------------------------------------------
        elif item.check_id == "windows_security_settings":
            uac_lua = data.get("uac_enable_lua")
            if uac_lua == 0:
                findings.append(
                    OSFindingCreate(
                        finding_type=OSFindingType.MISCONFIGURATION,
                        advisory_id="CONFIG-WIN-UAC-DISABLED",
                        title="User Account Control (UAC) Disabled in Windows Registry",
                        component_name="HKLM\\...\\Policies\\System:EnableLUA",
                        installed_version="0",
                        fixed_version="1",
                        severity=OSSeverity.HIGH,
                        confidence=OSConfidence.HIGH,
                        exploitability=OSExploitability.UNKNOWN,
                        advisory_source="cis_benchmark_windows",
                        match_basis="registry_direct_query",
                        description=(
                            "UAC is completely disabled (EnableLUA=0). Applications run with full administrative rights "
                            "without prompting for elevation, rendering the system vulnerable to silent privilege escalation."
                        ),
                    )
                )

            rdp_nla = data.get("rdp_nla_required")
            if rdp_nla is False:
                findings.append(
                    OSFindingCreate(
                        finding_type=OSFindingType.MISCONFIGURATION,
                        advisory_id="CONFIG-WIN-RDP-NLA-DISABLED",
                        title="Remote Desktop Network Level Authentication (NLA) Not Required",
                        component_name="HKLM\\...\\Terminal Server:UserAuthentication",
                        installed_version="0",
                        fixed_version="1",
                        severity=OSSeverity.MEDIUM,
                        confidence=OSConfidence.HIGH,
                        exploitability=OSExploitability.UNKNOWN,
                        advisory_source="cis_benchmark_windows",
                        match_basis="registry_direct_query",
                        description=(
                            "Remote Desktop allows connections without pre-authentication (UserAuthentication=0). "
                            "NLA must be enforced to mitigate pre-authentication exploits and unauthorized terminal sessions."
                        ),
                    )
                )

        # -------------------------------------------------------------
        # 4. Windows Defender Real-Time Protection
        # -------------------------------------------------------------
        elif item.check_id == "windows_defender_status":
            rtp_active = data.get("realtime_monitoring_active")
            if rtp_active is False:
                findings.append(
                    OSFindingCreate(
                        finding_type=OSFindingType.MISCONFIGURATION,
                        advisory_id="CONFIG-WIN-DEFENDER-RTP-OFF",
                        title="Windows Defender Real-Time Antivirus Protection Disabled",
                        component_name="HKLM\\...\\Windows Defender:DisableRealtimeMonitoring",
                        installed_version="Disabled",
                        fixed_version="Enabled",
                        severity=OSSeverity.HIGH,
                        confidence=OSConfidence.HIGH,
                        exploitability=OSExploitability.UNKNOWN,
                        advisory_source="cis_benchmark_windows",
                        match_basis="registry_direct_query",
                        description=(
                            "Windows Defender Real-Time Monitoring is explicitly turned off in the registry. "
                            "The system is not inspecting file creations or memory loads in real-time."
                        ),
                    )
                )

        # -------------------------------------------------------------
        # 5. Windows Firewall Profile Status
        # -------------------------------------------------------------
        elif item.check_id == "windows_firewall_status":
            public_on = data.get("public_enabled")
            if public_on is False:
                findings.append(
                    OSFindingCreate(
                        finding_type=OSFindingType.MISCONFIGURATION,
                        advisory_id="CONFIG-WIN-FIREWALL-PUBLIC-OFF",
                        title="Windows Firewall Disabled on Public Network Profile",
                        component_name="HKLM\\...\\FirewallPolicy\\PublicProfile:EnableFirewall",
                        installed_version="0",
                        fixed_version="1",
                        severity=OSSeverity.HIGH,
                        confidence=OSConfidence.HIGH,
                        exploitability=OSExploitability.UNKNOWN,
                        advisory_source="cis_benchmark_windows",
                        match_basis="registry_direct_query",
                        description=(
                            "The Windows Firewall is disabled on the Public network profile. Inbound filtering "
                            "is inactive when connected to untrusted networks."
                        ),
                    )
                )

            standard_on = data.get("standard_enabled")
            if standard_on is False:
                findings.append(
                    OSFindingCreate(
                        finding_type=OSFindingType.MISCONFIGURATION,
                        advisory_id="CONFIG-WIN-FIREWALL-STANDARD-OFF",
                        title="Windows Firewall Disabled on Standard/Private Network Profile",
                        component_name="HKLM\\...\\FirewallPolicy\\StandardProfile:EnableFirewall",
                        installed_version="0",
                        fixed_version="1",
                        severity=OSSeverity.MEDIUM,
                        confidence=OSConfidence.HIGH,
                        exploitability=OSExploitability.UNKNOWN,
                        advisory_source="cis_benchmark_windows",
                        match_basis="registry_direct_query",
                        description=(
                            "The Windows Firewall is disabled on the Standard/Private network profile. "
                            "Inbound filtering is inactive on local networks."
                        ),
                    )
                )

    return findings
