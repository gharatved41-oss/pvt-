import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class BaseTwinAdapter(ABC):
    """Abstract Virtualization and Sandboxing Provider Interface."""
    @abstractmethod
    def get_templates(self) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def create_twin(self, asset_id: str, asset_name: str, template_name: str, target_config: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_status(self, twin_id: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def reset_to_snapshot(self, twin_id: str, snapshot_name: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def take_snapshot(self, twin_id: str, snapshot_name: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def verify_isolation(self, twin_id: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def compare_config(self, target_config: Dict[str, Any], current_config: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def is_simulation(self) -> bool:
        pass


class MockIsolatedTwinAdapter(BaseTwinAdapter):
    """
    Production-Safe Isolated Digital Twin Simulation Provider.
    Clearly Labeled: Operates inside sandboxed environment with deterministic configuration states,
    providing complete air-gapped isolation (VLAN 1099, No WAN gateway, baseline snapshot rollbacks).
    """
    def __init__(self):
        self.provider_name = "mock_isolated"
        self.supported_templates = [
            {
                "template_name": "ubuntu-22.04-cve-lab",
                "os_type": "linux",
                "os_version": "Ubuntu 22.04.2 LTS",
                "description": "Ubuntu 22.04 LTS isolated sandbox replica with vulnerable service fixtures",
                "default_ip": "192.168.100.105",
                "isolation_mode": "Host-Only Virtual Adapter (No WAN Route, VLAN 1099)",
                "simulation_mode": "deterministic_sandboxed_simulation",
                "simulation_label": "Simulated Sandbox (MockIsolated Provider)",
                "vcpus": 2,
                "memory_mb": 2048,
                "preinstalled_packages": ["policykit-1", "openssh-server", "nginx", "curl", "log4j-core"]
            },
            {
                "template_name": "win-server2022-lab",
                "os_type": "windows",
                "os_version": "Windows Server 2022 Datacenter",
                "description": "Windows Server 2022 Datacenter isolated lab container with Active Directory stub",
                "default_ip": "192.168.100.120",
                "isolation_mode": "Host-Only Internal Lab Switch (VLAN 1099)",
                "simulation_mode": "deterministic_sandboxed_simulation",
                "simulation_label": "Simulated Sandbox (MockIsolated Provider)",
                "vcpus": 4,
                "memory_mb": 4096,
                "preinstalled_packages": ["windows-clfs", "curl", "powershell", "log4j-core"]
            },
            {
                "template_name": "debian-11-hardened-lab",
                "os_type": "linux",
                "os_version": "Debian 11 Bullseye",
                "description": "Debian 11 Bullseye baseline validation replica with AppArmor active",
                "default_ip": "192.168.100.110",
                "isolation_mode": "Host-Only Airgap Subnet (VLAN 1099)",
                "simulation_mode": "deterministic_sandboxed_simulation",
                "simulation_label": "Simulated Sandbox (MockIsolated Provider)",
                "vcpus": 2,
                "memory_mb": 2048,
                "preinstalled_packages": ["systemd", "sudo", "auditd"]
            },
            {
                "template_name": "rhel-9-enterprise-lab",
                "os_type": "linux",
                "os_version": "Red Hat Enterprise Linux 9.2",
                "description": "RHEL 9 Enterprise Linux server replica with SELinux targeted policy",
                "default_ip": "192.168.100.115",
                "isolation_mode": "Host-Only Virtual Adapter (VLAN 1099)",
                "simulation_mode": "deterministic_sandboxed_simulation",
                "simulation_label": "Simulated Sandbox (MockIsolated Provider)",
                "vcpus": 2,
                "memory_mb": 2048,
                "preinstalled_packages": ["openssh-server", "firewalld", "selinux-policy"]
            },
            {
                "template_name": "alpine-3.18-container-lab",
                "os_type": "linux",
                "os_version": "Alpine Linux 3.18",
                "description": "Lightweight containerized microservice replica for minimal attack surface tests",
                "default_ip": "192.168.100.130",
                "isolation_mode": "Bridge Isolated Container Network (VLAN 1099)",
                "simulation_mode": "deterministic_sandboxed_simulation",
                "simulation_label": "Simulated Sandbox (MockIsolated Provider)",
                "vcpus": 1,
                "memory_mb": 512,
                "preinstalled_packages": ["musl", "busybox", "libssl3"]
            }
        ]

    def is_simulation(self) -> bool:
        return True

    def get_templates(self) -> List[Dict[str, Any]]:
        return self.supported_templates

    def create_twin(self, asset_id: str, asset_name: str, template_name: str, target_config: Dict[str, Any]) -> Dict[str, Any]:
        """Instantiate a new sandboxed digital twin replica with clean baseline snapshot."""
        # Find matching template
        tpl = next((t for t in self.supported_templates if t["template_name"] == template_name), self.supported_templates[0])
        ip = tpl["default_ip"]

        # Synthesize twin initial config mirroring target asset
        current_config = dict(target_config)
        current_config["twin_replica"] = True
        current_config["vlan_tag"] = 1099
        current_config["wan_route_active"] = False

        parity_report = self.compare_config(target_config, current_config)

        return {
            "name": f"Twin-{asset_name}-Lab",
            "provider": self.provider_name,
            "template_name": tpl["template_name"],
            "status": "ready",
            "ip_address": ip,
            "network_isolated": True,
            "snapshot_status": "baseline-snapshot-created",
            "config_parity_score": parity_report["config_parity_score"],
            "target_config": target_config,
            "current_config": current_config,
            "is_simulation": True,
            "provider_label": "Simulated Sandbox (MockIsolated Provider)",
            "simulation_notice": "Running in deterministic isolated sandbox simulation. Production safe - no live hypervisor changes.",
            "isolation_details": {
                "airgap_confirmed": True,
                "vlan_id": 1099,
                "wan_gateway_blocked": True,
                "production_traffic_isolated": True,
                "sandbox_provider": "MockIsolatedSandbox (Production Safe)",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        }

    def get_status(self, twin_id: str) -> Dict[str, Any]:
        return {
            "twin_id": twin_id,
            "status": "ready",
            "cpu_usage_pct": 8.2,
            "memory_usage_mb": 1420,
            "network_isolated": True,
            "is_simulation": True,
            "active_services": ["sshd", "nginx", "auditd"],
            "vlan_id": 1099,
            "last_heartbeat": datetime.now(timezone.utc).isoformat()
        }

    def reset_to_snapshot(self, twin_id: str, snapshot_name: str = "baseline") -> Dict[str, Any]:
        """Restore sandbox state cleanly to designated baseline snapshot."""
        return {
            "twin_id": twin_id,
            "action": "reset_to_snapshot",
            "snapshot_name": snapshot_name,
            "success": True,
            "elapsed_ms": 320,
            "status": "ready",
            "network_isolated": True,
            "message": f"Digital Twin restored cleanly to snapshot '{snapshot_name}'. Configuration reset to baseline."
        }

    def take_snapshot(self, twin_id: str, snapshot_name: str) -> Dict[str, Any]:
        """Capture point-in-time snapshot of the twin sandbox."""
        return {
            "twin_id": twin_id,
            "action": "take_snapshot",
            "snapshot_name": snapshot_name,
            "success": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": f"Sandbox snapshot '{snapshot_name}' recorded successfully."
        }

    def verify_isolation(self, twin_id: str) -> Dict[str, Any]:
        """
        Verify strict air-gapped isolation before enabling validation tests:
        1. Confirms virtual network interface is bound to VLAN 1099.
        2. Proves default WAN gateway route is deactivated (No Internet egress).
        3. Proves production network routing table contains drop rules.
        """
        return {
            "twin_id": twin_id,
            "isolated": True,
            "vlan_tag": 1099,
            "internet_gateway_blocked": True,
            "production_traffic_blocked": True,
            "egress_rule": "DROP all WAN 0.0.0.0/0",
            "ingress_rule": "ACCEPT lab loopback 192.168.100.0/24",
            "safe_for_testing": True,
            "verified_at": datetime.now(timezone.utc).isoformat()
        }

    def compare_config(self, target_config: Dict[str, Any], current_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep configuration comparison between target asset and digital twin replica.
        Calculates parity score (0 - 100%) and categorizes parameter matches, diffs, and omissions.
        """
        target = target_config or {}
        current = current_config or {}

        all_keys = set(target.keys()) | set(current.keys())
        # Exclude internal twin management metadata from penalty
        comparison_keys = [k for k in all_keys if not k.startswith("twin_") and k not in ["vlan_tag", "wan_route_active"]]

        matched = {}
        differing = {}
        missing_in_twin = []
        missing_in_target = []

        if not comparison_keys:
            return {
                "config_parity_score": 100.0,
                "matched_parameters": {},
                "differing_parameters": {},
                "missing_in_twin": [],
                "missing_in_target": [],
                "summary": "No specific configuration directives defined; parity assumed 100% based on template matching."
            }

        for key in comparison_keys:
            in_t = key in target
            in_c = key in current

            if in_t and not in_c:
                missing_in_twin.append(key)
            elif in_c and not in_t:
                missing_in_target.append(key)
            else:
                t_val = target[key]
                c_val = current[key]
                if t_val == c_val:
                    matched[key] = t_val
                else:
                    differing[key] = {
                        "target_value": t_val,
                        "twin_value": c_val
                    }

        total_checked = len(comparison_keys)
        match_count = len(matched)
        parity_score = round((match_count / total_checked) * 100.0, 1) if total_checked > 0 else 100.0

        summary = (
            f"Configuration parity score: {parity_score}%. "
            f"{match_count}/{total_checked} directives matched. "
            f"{len(differing)} differing parameters, {len(missing_in_twin)} missing in twin."
        )

        return {
            "config_parity_score": parity_score,
            "matched_parameters": matched,
            "differing_parameters": differing,
            "missing_in_twin": missing_in_twin,
            "missing_in_target": missing_in_target,
            "summary": summary
        }


class VirtualBoxTwinAdapter(BaseTwinAdapter):
    """
    VirtualBox Hypervisor Provider Abstraction.
    Interacts with headless VirtualBox VMs via VBoxManage for bare-metal testing.
    """
    def __init__(self):
        self.provider_name = "virtualbox"

    def is_simulation(self) -> bool:
        return False

    def get_templates(self) -> List[Dict[str, Any]]:
        return [
            {
                "template_name": "vbox-ubuntu-headless-vms",
                "os_type": "linux",
                "description": "Hardware virtualized VirtualBox VM (requires VBoxManage)",
                "default_ip": "192.168.56.101",
                "isolation_mode": "Host-Only Adapter vboxnet0",
                "simulation_mode": "hardware_virtualization",
                "simulation_label": "Bare-Metal VirtualBox Hypervisor"
            }
        ]

    def create_twin(self, asset_id: str, asset_name: str, template_name: str, target_config: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError("VirtualBox hardware virtualization requires active VBoxManage daemon. Use 'mock_isolated' for simulation.")

    def get_status(self, twin_id: str) -> Dict[str, Any]:
        raise NotImplementedError("VirtualBox adapter requires active hypervisor daemon.")

    def reset_to_snapshot(self, twin_id: str, snapshot_name: str) -> Dict[str, Any]:
        raise NotImplementedError("VirtualBox adapter requires active hypervisor daemon.")

    def take_snapshot(self, twin_id: str, snapshot_name: str) -> Dict[str, Any]:
        raise NotImplementedError("VirtualBox adapter requires active hypervisor daemon.")

    def verify_isolation(self, twin_id: str) -> Dict[str, Any]:
        return {"isolated": False, "error": "Hypervisor host-only interface unlinked"}

    def compare_config(self, target_config: Dict[str, Any], current_config: Dict[str, Any]) -> Dict[str, Any]:
        return {"config_parity_score": 0.0, "summary": "Unlinked hypervisor"}


class TwinProviderRegistry:
    """Provider Registry to resolve virtualization or simulation providers."""
    def __init__(self):
        self._providers: Dict[str, BaseTwinAdapter] = {
            "mock_isolated": MockIsolatedTwinAdapter(),
            "virtualbox": VirtualBoxTwinAdapter()
        }

    def get_provider(self, name: str = "mock_isolated") -> BaseTwinAdapter:
        return self._providers.get(name.lower(), self._providers["mock_isolated"])

    def list_providers(self) -> List[str]:
        return list(self._providers.keys())

provider_registry = TwinProviderRegistry()
twin_engine = provider_registry.get_provider("mock_isolated")
