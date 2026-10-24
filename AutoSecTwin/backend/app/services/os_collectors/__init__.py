"""Operating system read-only security evidence collectors."""

from app.services.os_collectors.base import BaseOSCollector
from app.services.os_collectors.config_evaluator import (
    evaluate_security_configuration_evidence,
)
from app.services.os_collectors.linux import (
    LinuxDpkgStatusCollector,
    LinuxOSReleaseCollector,
)
from app.services.os_collectors.linux_security import (
    LinuxKernelHardeningCollector,
    LinuxPackageUpdateStatusCollector,
    LinuxSSHConfigCollector,
)
from app.services.os_collectors.manager import OSCollectorManager
from app.services.os_collectors.windows import (
    WindowsInstalledSoftwareCollector,
    WindowsOSIdentityCollector,
)
from app.services.os_collectors.windows_security import (
    WindowsDefenderStatusCollector,
    WindowsFirewallProfileCollector,
    WindowsSecuritySettingsCollector,
)

__all__ = [
    "BaseOSCollector",
    "OSCollectorManager",
    "LinuxOSReleaseCollector",
    "LinuxDpkgStatusCollector",
    "LinuxKernelHardeningCollector",
    "LinuxSSHConfigCollector",
    "LinuxPackageUpdateStatusCollector",
    "WindowsOSIdentityCollector",
    "WindowsInstalledSoftwareCollector",
    "WindowsDefenderStatusCollector",
    "WindowsFirewallProfileCollector",
    "WindowsSecuritySettingsCollector",
    "evaluate_security_configuration_evidence",
]
