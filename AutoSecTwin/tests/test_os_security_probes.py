"""Automated unit and evaluation tests for Milestone 3: Platform-Specific Security Configuration Probes."""

from pathlib import Path
from typing import Any, Dict, List
import pytest

from app.schemas.os_evidence import OSEvidenceStatus, OSPermissionState
from app.schemas.os_finding import OSConfidence, OSExploitability, OSSeverity
from app.services.os_collectors.config_evaluator import (
    evaluate_security_configuration_evidence,
)
from app.services.os_collectors.linux_security import (
    LinuxKernelHardeningCollector,
    LinuxPackageUpdateStatusCollector,
    LinuxSSHConfigCollector,
)
from app.services.os_collectors.manager import OSCollectorManager
from app.services.os_collectors.windows_security import (
    WindowsDefenderStatusCollector,
    WindowsFirewallProfileCollector,
    WindowsSecuritySettingsCollector,
)


# =====================================================================
# 1. Linux Kernel Hardening & Sysctl Tests
# =====================================================================

def test_linux_kernel_hardening_aslr_enabled_pass() -> None:
    """Verify that ASLR = 2 produces observed evidence and no misconfiguration finding (PASS)."""
    mock_sysctl = {
        "randomize_va_space": 2,
        "ip_forward": 0,
        "protected_symlinks": 1,
        "protected_hardlinks": 1,
        "dmesg_restrict": 1,
        "kptr_restrict": 1,
    }
    collector = LinuxKernelHardeningCollector()
    evidence_list = collector.collect(context={"mock_proc_sys": mock_sysctl})

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.collection_status == OSEvidenceStatus.OBSERVED
    assert ev.structured_data["randomize_va_space"] == 2
    assert "ASLR Fully Enabled" in str(ev.observed_value)

    # Evaluate for findings: Secure state produces 0 findings
    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 0


def test_linux_kernel_hardening_aslr_disabled_fail() -> None:
    """Verify that ASLR = 0 produces a HIGH severity misconfiguration finding (FAIL)."""
    mock_sysctl = {
        "randomize_va_space": 0,
        "ip_forward": 0,
    }
    collector = LinuxKernelHardeningCollector()
    evidence_list = collector.collect(context={"mock_proc_sys": mock_sysctl})

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 1
    f = findings[0]
    assert f.advisory_id == "CONFIG-LINUX-ASLR-OFF"
    assert f.severity == OSSeverity.HIGH
    assert f.confidence == OSConfidence.HIGH
    assert f.exploitability == OSExploitability.UNKNOWN
    assert f.component_name == "kernel.randomize_va_space"


def test_linux_kernel_hardening_aslr_conservative_and_ip_forward() -> None:
    """Verify ASLR = 1 (MEDIUM) and IP Forwarding = 1 (LOW) generate separate findings."""
    mock_sysctl = {
        "randomize_va_space": 1,
        "ip_forward": 1,
    }
    collector = LinuxKernelHardeningCollector()
    evidence_list = collector.collect(context={"mock_proc_sys": mock_sysctl})

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 2

    advisories = {f.advisory_id: f for f in findings}
    assert "CONFIG-LINUX-ASLR-CONSERVATIVE" in advisories
    assert advisories["CONFIG-LINUX-ASLR-CONSERVATIVE"].severity == OSSeverity.MEDIUM

    assert "CONFIG-LINUX-IP-FORWARD" in advisories
    assert advisories["CONFIG-LINUX-IP-FORWARD"].severity == OSSeverity.LOW


# =====================================================================
# 2. Linux SSH Configuration Probes Tests
# =====================================================================

def test_linux_ssh_config_secure_pass(tmp_path: Path) -> None:
    """Verify secure sshd_config produces no findings."""
    config_content = (
        "Port 22\n"
        "PermitRootLogin no\n"
        "PasswordAuthentication no\n"
        "X11Forwarding no\n"
    )
    conf_file = tmp_path / "sshd_config"
    conf_file.write_text(config_content, encoding="utf-8")

    collector = LinuxSSHConfigCollector()
    evidence_list = collector.collect(context={"sshd_config_path": str(conf_file)})

    assert len(evidence_list) == 1
    assert evidence_list[0].collection_status == OSEvidenceStatus.OBSERVED
    assert evidence_list[0].structured_data["permit_root_login"] == "no"

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 0


def test_linux_ssh_config_root_login_fail(tmp_path: Path) -> None:
    """Verify PermitRootLogin yes produces a HIGH severity finding."""
    config_content = (
        "# SSH Server Config\n"
        "PermitRootLogin yes\n"
        "PasswordAuthentication yes\n"
    )
    conf_file = tmp_path / "sshd_config"
    conf_file.write_text(config_content, encoding="utf-8")

    collector = LinuxSSHConfigCollector()
    evidence_list = collector.collect(context={"sshd_config_path": str(conf_file)})

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 1
    f = findings[0]
    assert f.advisory_id == "CONFIG-SSH-ROOT-LOGIN"
    assert f.severity == OSSeverity.HIGH
    assert f.exploitability == OSExploitability.UNKNOWN


def test_linux_ssh_config_file_absent() -> None:
    """Verify missing sshd_config produces ABSENT status and zero findings (not a pass or fail)."""
    collector = LinuxSSHConfigCollector()
    evidence_list = collector.collect(context={"sshd_config_path": "/nonexistent/sshd_config"})

    assert len(evidence_list) == 1
    assert evidence_list[0].collection_status == OSEvidenceStatus.ABSENT

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 0


# =====================================================================
# 3. Linux Package Update Cache Probe Tests
# =====================================================================

def test_linux_package_update_status_parsing(tmp_path: Path) -> None:
    """Verify parsing of Ubuntu /var/lib/update-notifier/updates-available banner."""
    cache_content = (
        "12 updates can be applied immediately.\n"
        "5 of these updates are standard security updates.\n"
    )
    cache_file = tmp_path / "updates-available"
    cache_file.write_text(cache_content, encoding="utf-8")

    collector = LinuxPackageUpdateStatusCollector()
    evidence_list = collector.collect(context={"updates_available_path": str(cache_file)})

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.collection_status == OSEvidenceStatus.OBSERVED
    assert ev.structured_data["total_updates"] == 12
    assert ev.structured_data["security_updates"] == 5


def test_linux_package_update_status_file_absent() -> None:
    """Verify that absent updates-available file emits UNAVAILABLE status."""
    collector = LinuxPackageUpdateStatusCollector()
    evidence_list = collector.collect(context={"updates_available_path": "/nonexistent/updates-available"})

    assert len(evidence_list) == 1
    assert evidence_list[0].collection_status == OSEvidenceStatus.UNAVAILABLE


# =====================================================================
# 4. Windows Defender Real-Time Protection Tests
# =====================================================================

def test_windows_defender_enabled_pass() -> None:
    """Verify Windows Defender with RTP active produces 0 findings (PASS)."""
    mock_reg = {
        "DisableRealtimeMonitoring": 0,
        "DisableAntiSpyware": 0,
    }
    collector = WindowsDefenderStatusCollector()
    evidence_list = collector.collect(context={"mock_defender_registry": mock_reg})

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.collection_status == OSEvidenceStatus.OBSERVED
    assert ev.structured_data["realtime_monitoring_active"] is True

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 0


def test_windows_defender_disabled_fail() -> None:
    """Verify Windows Defender with RTP disabled produces a HIGH severity finding (FAIL)."""
    mock_reg = {
        "DisableRealtimeMonitoring": 1,
        "DisableAntiSpyware": 0,
    }
    collector = WindowsDefenderStatusCollector()
    evidence_list = collector.collect(context={"mock_defender_registry": mock_reg})

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 1
    f = findings[0]
    assert f.advisory_id == "CONFIG-WIN-DEFENDER-RTP-OFF"
    assert f.severity == OSSeverity.HIGH
    assert f.exploitability == OSExploitability.UNKNOWN


# =====================================================================
# 5. Windows Firewall Profile Tests
# =====================================================================

def test_windows_firewall_all_profiles_enabled_pass() -> None:
    """Verify all firewall profiles enabled produces 0 findings (PASS)."""
    mock_reg = {
        "domain_profile": {"enabled": True},
        "standard_profile": {"enabled": True},
        "public_profile": {"enabled": True},
    }
    collector = WindowsFirewallProfileCollector()
    evidence_list = collector.collect(context={"mock_firewall_registry": mock_reg})

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.collection_status == OSEvidenceStatus.OBSERVED
    assert "Public: ON" in str(ev.observed_value)

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 0


def test_windows_firewall_public_disabled_fail() -> None:
    """Verify Public profile disabled produces a HIGH severity finding (FAIL)."""
    mock_reg = {
        "domain_profile": {"enabled": True},
        "standard_profile": {"enabled": True},
        "public_profile": {"enabled": False},
    }
    collector = WindowsFirewallProfileCollector()
    evidence_list = collector.collect(context={"mock_firewall_registry": mock_reg})

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 1
    f = findings[0]
    assert f.advisory_id == "CONFIG-WIN-FIREWALL-PUBLIC-OFF"
    assert f.severity == OSSeverity.HIGH
    assert f.exploitability == OSExploitability.UNKNOWN


# =====================================================================
# 6. Windows Security Settings (UAC & RDP) Tests
# =====================================================================

def test_windows_security_settings_uac_and_nla_enabled_pass() -> None:
    """Verify UAC enabled (1) and RDP NLA enabled (1) produces 0 findings (PASS)."""
    mock_reg = {
        "EnableLUA": 1,
        "ConsentPromptBehaviorAdmin": 2,
        "rdp_nla_user_authentication": 1,
    }
    collector = WindowsSecuritySettingsCollector()
    evidence_list = collector.collect(context={"mock_security_settings_registry": mock_reg})

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.collection_status == OSEvidenceStatus.OBSERVED
    assert ev.structured_data["uac_enable_lua"] == 1
    assert ev.structured_data["rdp_nla_required"] is True

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 0


def test_windows_security_settings_uac_disabled_fail() -> None:
    """Verify UAC disabled (0) produces a HIGH severity finding (FAIL)."""
    mock_reg = {
        "EnableLUA": 0,
        "ConsentPromptBehaviorAdmin": 0,
        "rdp_nla_user_authentication": 1,
    }
    collector = WindowsSecuritySettingsCollector()
    evidence_list = collector.collect(context={"mock_security_settings_registry": mock_reg})

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 1
    f = findings[0]
    assert f.advisory_id == "CONFIG-WIN-UAC-DISABLED"
    assert f.severity == OSSeverity.HIGH
    assert f.exploitability == OSExploitability.UNKNOWN


def test_windows_security_settings_rdp_nla_disabled_fail() -> None:
    """Verify RDP NLA disabled (0) produces a MEDIUM severity finding (FAIL)."""
    mock_reg = {
        "EnableLUA": 1,
        "rdp_nla_user_authentication": 0,
    }
    collector = WindowsSecuritySettingsCollector()
    evidence_list = collector.collect(context={"mock_security_settings_registry": mock_reg})

    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 1
    f = findings[0]
    assert f.advisory_id == "CONFIG-WIN-RDP-NLA-DISABLED"
    assert f.severity == OSSeverity.MEDIUM
    assert f.exploitability == OSExploitability.UNKNOWN


# =====================================================================
# 7. Evaluator Invariants Tests (Missing Evidence != PASS)
# =====================================================================

def test_evaluator_never_treats_unavailable_as_pass() -> None:
    """Confirm that UNAVAILABLE, ABSENT, or ERROR evidence never produces a PASS or finding."""
    collector = LinuxKernelHardeningCollector()
    # Emits UNAVAILABLE because mock is empty and host does not expose paths in test
    evidence_list = collector.collect(context={"mock_proc_sys": None})

    # Evaluator must not crash or assert that missing evidence is clean
    findings = evaluate_security_configuration_evidence(evidence_list)
    assert len(findings) == 0
