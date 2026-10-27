import pytest
from app.services.twin_engine import (
    BaseTwinAdapter, MockIsolatedTwinAdapter, VirtualBoxTwinAdapter,
    TwinProviderRegistry, twin_engine, provider_registry
)
from app.models.models import Asset, DigitalTwin, VulnerabilityFinding, Assessment

def test_phase4_environment_templates_and_simulation_labels(client, auth_headers):
    """Verify preconfigured environment templates, airgap VLAN 1099, and simulation labels."""
    res = client.get("/api/v1/twins/templates", headers=auth_headers)
    assert res.status_code == 200
    templates = res.json()
    assert len(templates) >= 5

    template_names = [t["template_name"] for t in templates]
    assert "ubuntu-22.04-cve-lab" in template_names
    assert "debian-11-hardened-lab" in template_names
    assert "rhel-9-enterprise-lab" in template_names
    assert "alpine-3.18-container-lab" in template_names
    assert "win-server2022-lab" in template_names

    for tpl in templates:
        assert "VLAN 1099" in tpl["isolation_mode"]
        assert tpl["simulation_mode"] == "deterministic_sandboxed_simulation"
        assert "Simulated Sandbox" in tpl["simulation_label"]
        assert "default_ip" in tpl
        assert tpl["vcpus"] >= 1
        assert tpl["memory_mb"] >= 512

def test_phase4_virtualization_provider_abstraction(client, auth_headers):
    """Verify provider registry, adapter abstraction interface, and simulation metadata."""
    res = client.get("/api/v1/twins/providers", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["active_provider"] == "mock_isolated"
    assert data["is_simulation"] is True

    providers = data["available_providers"]
    assert "mock_isolated" in providers
    assert "virtualbox" in providers

    # Verify adapter registry lookup
    mock_adapter = provider_registry.get_provider("mock_isolated")
    assert isinstance(mock_adapter, MockIsolatedTwinAdapter)
    assert mock_adapter.is_simulation() is True

    vbox_adapter = provider_registry.get_provider("virtualbox")
    assert isinstance(vbox_adapter, VirtualBoxTwinAdapter)

    # Unknown provider defaults to mock_isolated
    fallback = provider_registry.get_provider("unknown_hypervisor")
    assert isinstance(fallback, MockIsolatedTwinAdapter)

def test_phase4_twin_records_crud_and_parity_scoring(client, auth_headers, db_session):
    """Verify twin creation with asset config snapshot, parity scoring, and simulation tags."""
    # 1. Create a target production asset
    asset_res = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "Phase4-Core-Target",
        "ip_address": "10.0.4.15",
        "hostname": "core-p4-srv",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04 LTS",
        "environment": "production",
        "criticality": "high",
        "description": "Production server for Phase 4 Digital Twin validation"
    })
    assert asset_res.status_code == 201
    asset_id = asset_res.json()["id"]

    # 2. Deploy Digital Twin replica
    twin_res = client.post("/api/v1/twins", headers=auth_headers, json={
        "asset_id": asset_id,
        "name": "Twin-Core-Target-Lab",
        "template_name": "ubuntu-22.04-cve-lab",
        "provider": "mock_isolated"
    })
    assert twin_res.status_code == 201
    twin_data = twin_res.json()
    twin_id = twin_data["id"]

    assert twin_data["name"] == "Twin-Core-Target-Lab"
    assert twin_data["status"] == "ready"
    assert twin_data["network_isolated"] is True
    assert twin_data["ip_address"] == "192.168.100.105"
    assert twin_data["is_simulation"] is True
    assert "Simulated Sandbox" in twin_data["provider_label"]
    assert "isolated sandbox" in twin_data["simulation_notice"].lower()
    assert twin_data["config_parity_score"] == 100.0

    # 3. Retrieve Twin by ID
    get_res = client.get(f"/api/v1/twins/{twin_id}", headers=auth_headers)
    assert get_res.status_code == 200
    assert get_res.json()["id"] == twin_id

    # 4. Filter Twins by Asset ID
    list_res = client.get(f"/api/v1/twins?asset_id={asset_id}", headers=auth_headers)
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

def test_phase4_configuration_comparison(client, auth_headers):
    """Verify deep configuration comparison and parity penalty computation."""
    # 1. Test unit parity logic
    target_cfg = {
        "kernel_release": "5.15.0-91-generic",
        "ssh_ciphers": "aes256-gcm@openssh.com",
        "selinux_mode": "enforcing",
        "timezone": "UTC"
    }
    # Current config with 1 match, 1 difference, 1 missing in twin, 1 extra in twin
    current_cfg = {
        "kernel_release": "5.15.0-91-generic", # match
        "ssh_ciphers": "aes128-ctr",           # diff
        "timezone": "UTC",                     # match
        "new_debug_flag": True                 # missing in target
        # selinux_mode missing in twin
    }
    diff = twin_engine.compare_config(target_cfg, current_cfg)
    assert 40.0 <= diff["config_parity_score"] <= 60.0
    assert "kernel_release" in diff["matched_parameters"]
    assert "ssh_ciphers" in diff["differing_parameters"]
    assert "selinux_mode" in diff["missing_in_twin"]
    assert "new_debug_flag" in diff["missing_in_target"]

    # 2. Test configuration comparison endpoint
    # Create asset and twin
    a_res = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "Phase4-Config-Asset",
        "ip_address": "10.0.4.20",
        "hostname": "cfg-p4-srv",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04",
        "environment": "staging",
        "criticality": "medium"
    })
    asset_id = a_res.json()["id"]

    t_res = client.post("/api/v1/twins", headers=auth_headers, json={
        "asset_id": asset_id,
        "name": "Twin-Config-Compare",
        "template_name": "ubuntu-22.04-cve-lab"
    })
    twin_id = t_res.json()["id"]

    comp_res = client.get(f"/api/v1/twins/{twin_id}/compare-config", headers=auth_headers)
    assert comp_res.status_code == 200
    comp_data = comp_res.json()
    assert comp_data["twin_id"] == twin_id
    assert comp_data["config_parity_score"] >= 90.0
    assert "matched_parameters" in comp_data
    assert "differing_parameters" in comp_data

def test_phase4_lifecycle_states_and_snapshot_reset(client, auth_headers):
    """Verify lifecycle actions: start, stop, snapshot creation, baseline rollback, and isolation."""
    # Create asset and twin
    a_res = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "Phase4-Lifecycle-Asset",
        "ip_address": "10.0.4.30",
        "hostname": "life-p4-srv",
        "os_type": "linux",
        "os_version": "Debian 12",
        "environment": "development",
        "criticality": "low"
    })
    asset_id = a_res.json()["id"]

    t_res = client.post("/api/v1/twins", headers=auth_headers, json={
        "asset_id": asset_id,
        "name": "Twin-Lifecycle-Lab",
        "template_name": "debian-11-hardened-lab"
    })
    twin_id = t_res.json()["id"]
    assert t_res.json()["status"] == "ready"

    # 1. Action: Stop
    stop_res = client.post(f"/api/v1/twins/{twin_id}/actions", headers=auth_headers, json={"action": "stop"})
    assert stop_res.status_code == 200
    check_stop = client.get(f"/api/v1/twins/{twin_id}", headers=auth_headers)
    assert check_stop.json()["status"] == "stopped"

    # 2. Action: Start
    start_res = client.post(f"/api/v1/twins/{twin_id}/actions", headers=auth_headers, json={"action": "start"})
    assert start_res.status_code == 200
    check_start = client.get(f"/api/v1/twins/{twin_id}", headers=auth_headers)
    assert check_start.json()["status"] == "ready"

    # 3. Action: Create Snapshot
    snap_res = client.post(f"/api/v1/twins/{twin_id}/actions", headers=auth_headers, json={
        "action": "create_snapshot",
        "snapshot_name": "pre-exploit-checkpoint-01"
    })
    assert snap_res.status_code == 200
    check_snap = client.get(f"/api/v1/twins/{twin_id}", headers=auth_headers)
    assert check_snap.json()["snapshot_status"] == "pre-exploit-checkpoint-01"

    # 4. Action: Reset to Snapshot
    reset_res = client.post(f"/api/v1/twins/{twin_id}/actions", headers=auth_headers, json={
        "action": "reset_snapshot",
        "snapshot_name": "baseline"
    })
    assert reset_res.status_code == 200
    check_reset = client.get(f"/api/v1/twins/{twin_id}", headers=auth_headers)
    assert "restored-to-baseline" in check_reset.json()["snapshot_status"]
    assert check_reset.json()["status"] == "ready"

    # 5. Action: Verify Isolation telemetry endpoint
    iso_res = client.get(f"/api/v1/twins/{twin_id}/isolation", headers=auth_headers)
    assert iso_res.status_code == 200
    iso_data = iso_res.json()
    assert iso_data["isolated"] is True
    assert iso_data["vlan_tag"] == 1099
    assert iso_data["internet_gateway_blocked"] is True

def test_phase4_isolation_verification_enforcement_in_validation(client, auth_headers, db_session):
    """Verify that validation probes are strictly blocked if twin is not ready or unisolated."""
    # 1. Setup asset, assessment, and finding
    asset = Asset(
        name="Phase4-Validation-Asset",
        ip_address="10.0.4.40",
        hostname="val-target",
        os_type="linux",
        os_version="Ubuntu 22.04",
        environment="production",
        criticality="critical"
    )
    db_session.add(asset)
    db_session.commit()

    assessment = Assessment(
        asset_id=asset.id,
        title="Phase 4 Isolation Test Assessment",
        status="completed"
    )
    db_session.add(assessment)
    db_session.commit()

    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2021-4034",
        title="Polkit pkexec Local Privilege Escalation",
        affected_component="policykit-1",
        installed_version="0.105-26",
        fixed_version="0.105-31",
        cvss_v3_score=7.8,
        cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity="high",
        detection_status="detected",
        risk_score=75.0,
        risk_category="high",
        confidence_score=0.85,
        contributing_factors={"cvss": 7.8},
        recommended_priority="P1",
        risk_explanation="High risk polkit vulnerability"
    )
    db_session.add(finding)
    db_session.commit()

    # 2. Create twin
    twin = DigitalTwin(
        asset_id=asset.id,
        name="Twin-Validation-Check",
        provider="mock_isolated",
        template_name="ubuntu-22.04-cve-lab",
        status="stopped", # STOPPED STATE
        ip_address="192.168.100.110",
        network_isolated=True,
        snapshot_status="baseline",
        config_parity_score=100.0
    )
    db_session.add(twin)
    db_session.commit()

    # Attempt validation while twin is STOPPED -> MUST BE BLOCKED (HTTP 400)
    val_stopped = client.post("/api/v1/validation/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id,
        "procedure_code": "PROC-SEC-PKEXEC-01"
    })
    assert val_stopped.status_code == 400
    assert "must be in 'ready' state" in val_stopped.json()["detail"]

    # Now make twin ready, but set network_isolated = False -> MUST BE BLOCKED (HTTP 400)
    twin.status = "ready"
    twin.network_isolated = False
    db_session.commit()

    val_unisolated = client.post("/api/v1/validation/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id,
        "procedure_code": "PROC-SEC-PKEXEC-01"
    })
    assert val_unisolated.status_code == 400
    assert "not marked as network isolated" in val_unisolated.json()["detail"]

    # Now restore network isolation -> Validation MUST SUCCEED (HTTP 201)
    twin.network_isolated = True
    db_session.commit()

    val_success = client.post("/api/v1/validation/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id,
        "procedure_code": "PROC-SEC-PKEXEC-01"
    })
    assert val_success.status_code == 201
    run_data = val_success.json()
    assert run_data["status"] == "completed"
    assert run_data["outcome"] == "confirmed"
    assert "VULNERABILITY CONFIRMED IN ISOLATED TWIN" in run_data["test_output"]

    # Verify twin status was restored back to 'ready' after execution
    db_session.refresh(twin)
    assert twin.status == "ready"

def test_phase4_twin_decommission(client, auth_headers):
    """Verify twin record deletion and resource cleanup."""
    a_res = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "Phase4-Decom-Asset",
        "ip_address": "10.0.4.50",
        "hostname": "decom-p4-srv",
        "os_type": "linux",
        "os_version": "Alpine 3.18",
        "environment": "development",
        "criticality": "low"
    })
    asset_id = a_res.json()["id"]

    t_res = client.post("/api/v1/twins", headers=auth_headers, json={
        "asset_id": asset_id,
        "name": "Twin-To-Decommission",
        "template_name": "alpine-3.18-container-lab"
    })
    twin_id = t_res.json()["id"]

    # Delete twin
    del_res = client.delete(f"/api/v1/twins/{twin_id}", headers=auth_headers)
    assert del_res.status_code == 200
    assert "decommissioned successfully" in del_res.json()["message"]

    # Confirm twin is gone
    get_res = client.get(f"/api/v1/twins/{twin_id}", headers=auth_headers)
    assert get_res.status_code == 404
