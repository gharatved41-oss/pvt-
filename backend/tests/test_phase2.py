import os
import json
import pytest
from app.services.inventory_parser import InventoryParser, InventoryParseException
from app.services.cve_service import is_version_vulnerable, cve_service, clean_version_str

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app", "fixtures", "sample_inventories")

def test_phase2_asset_lifecycle(client, auth_headers):
    """Test asset creation, listing, filtering, updating, and deletion."""
    # 1. Create asset
    asset_data = {
        "name": "Phase 2 Edge Gateway",
        "ip_address": "192.168.50.10",
        "hostname": "edge-gw-p2",
        "os_type": "linux",
        "os_version": "Debian 11 Bullseye",
        "environment": "staging",
        "criticality": "high",
        "description": "Perimeter proxy host"
    }
    res = client.post("/api/v1/assets", headers=auth_headers, json=asset_data)
    assert res.status_code == 201
    created = res.json()
    asset_id = created["id"]
    assert created["hostname"] == "edge-gw-p2"
    assert created["status"] == "active"

    # 2. Get asset by ID
    get_res = client.get(f"/api/v1/assets/{asset_id}", headers=auth_headers)
    assert get_res.status_code == 200
    assert get_res.json()["name"] == "Phase 2 Edge Gateway"

    # 3. Filter assets by environment
    list_res = client.get("/api/v1/assets?environment=staging", headers=auth_headers)
    assert list_res.status_code == 200
    items = list_res.json()
    assert any(a["id"] == asset_id for a in items)

    # 4. Update asset
    upd_res = client.put(f"/api/v1/assets/{asset_id}", headers=auth_headers, json={
        "criticality": "critical",
        "description": "Updated mission-critical boundary gateway"
    })
    assert upd_res.status_code == 200
    assert upd_res.json()["criticality"] == "critical"

    # 5. Schema validation failure on invalid os_type
    bad_res = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "Invalid Host",
        "ip_address": "10.0.0.1",
        "hostname": "bad-host",
        "os_type": "freebsd",  # only linux or windows accepted
        "os_version": "13.0"
    })
    assert bad_res.status_code == 422

    # Clean up asset
    del_res = client.delete(f"/api/v1/assets/{asset_id}", headers=auth_headers)
    assert del_res.status_code == 200

def test_phase2_inventory_validation_and_json_import(client, auth_headers):
    """Test JSON inventory parsing, validation endpoint, and successful snapshot recording."""
    # Create test asset
    asset_res = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "JSON Import Test Host",
        "ip_address": "10.10.1.5",
        "hostname": "json-test-01",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04 LTS"
    })
    asset_id = asset_res.json()["id"]

    # 1. Test validation endpoint with raw JSON content
    valid_path = os.path.join(FIXTURES_DIR, "ubuntu_server_inventory.json")
    with open(valid_path, "r", encoding="utf-8") as f:
        valid_json_text = f.read()

    val_res = client.post(
        f"/api/v1/assets/{asset_id}/inventory/validate",
        headers=auth_headers,
        data={"raw_content": valid_json_text, "format_type": "json"}
    )
    assert val_res.status_code == 200
    val_data = val_res.json()
    assert val_data["is_valid"] is True
    assert val_data["valid_packages_count"] >= 5
    assert len(val_data["errors"]) == 0

    # 2. Test import with valid JSON
    import_res = client.post(
        f"/api/v1/assets/{asset_id}/inventory",
        headers=auth_headers,
        data={"raw_content": valid_json_text, "format_type": "json"}
    )
    assert import_res.status_code == 200
    snap = import_res.json()
    assert snap["asset_id"] == asset_id
    assert snap["format"] == "json"
    assert snap["packages_count"] >= 5
    assert "_validation_summary" in snap["configuration_metadata"]

    # 3. Test snapshots list for asset
    snaps_res = client.get(f"/api/v1/assets/{asset_id}/snapshots", headers=auth_headers)
    assert snaps_res.status_code == 200
    assert len(snaps_res.json()) >= 1

    # 4. Test malformed JSON rejection
    malformed_path = os.path.join(FIXTURES_DIR, "malformed_syntax.json")
    with open(malformed_path, "r", encoding="utf-8") as f:
        malformed_text = f.read()

    bad_import = client.post(
        f"/api/v1/assets/{asset_id}/inventory",
        headers=auth_headers,
        data={"raw_content": malformed_text, "format_type": "json"}
    )
    assert bad_import.status_code == 400
    assert "Invalid JSON format" in bad_import.json()["detail"]

    # Clean up
    client.delete(f"/api/v1/assets/{asset_id}", headers=auth_headers)

def test_phase2_inventory_csv_import_and_headers(client, auth_headers):
    """Test CSV inventory import with multiple alternative header names."""
    asset_res = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "CSV Import Test Host",
        "ip_address": "10.10.2.10",
        "hostname": "csv-test-01",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04 LTS"
    })
    asset_id = asset_res.json()["id"]

    # 1. Standard CSV fixture import
    csv_path = os.path.join(FIXTURES_DIR, "ubuntu_server_inventory.csv")
    with open(csv_path, "r", encoding="utf-8") as f:
        csv_text = f.read()

    import_res = client.post(
        f"/api/v1/assets/{asset_id}/inventory",
        headers=auth_headers,
        data={"raw_content": csv_text, "format_type": "csv"}
    )
    assert import_res.status_code == 200
    snap = import_res.json()
    assert snap["format"] == "csv"
    assert snap["packages_count"] >= 5

    # 2. Alternative header variants (name, version, arch) with comment lines
    custom_csv = (
        "# Automatic inventory dump\n"
        "name,version,arch\n"
        "openssh-server,8.9p1,amd64\n"
        "curl,7.81.0,amd64\n"
    )
    custom_res = client.post(
        f"/api/v1/assets/{asset_id}/inventory",
        headers=auth_headers,
        data={"raw_content": custom_csv, "format_type": "csv"}
    )
    assert custom_res.status_code == 200
    assert custom_res.json()["packages_count"] == 2

    # 3. Invalid headers rejection
    bad_csv_path = os.path.join(FIXTURES_DIR, "invalid_headers.csv")
    with open(bad_csv_path, "r", encoding="utf-8") as f:
        bad_csv = f.read()

    bad_res = client.post(
        f"/api/v1/assets/{asset_id}/inventory",
        headers=auth_headers,
        data={"raw_content": bad_csv, "format_type": "csv"}
    )
    assert bad_res.status_code == 400

    # Clean up
    client.delete(f"/api/v1/assets/{asset_id}", headers=auth_headers)

def test_phase2_cve_semantic_version_range_edge_cases():
    """Verify version normalization and boundary checks across Linux and Windows packages."""
    # Polkit PwnKit CVE-2021-4034: 0.105-0 <= ver <= 0.105-31
    assert is_version_vulnerable("0.105-26ubuntu0.1", "0.105-0", "0.105-31") is True
    assert is_version_vulnerable("0.105-31", "0.105-0", "0.105-31") is True
    assert is_version_vulnerable("0.105-31.1", "0.105-0", "0.105-31") is False
    assert is_version_vulnerable("0.105-32", "0.105-0", "0.105-31") is False

    # OpenSSH CVE-2023-38408: 5.5p1 <= ver <= 9.3p1 (with epoch 1:)
    assert is_version_vulnerable("1:8.9p1-3ubuntu0.1", "5.5p1", "9.3p1") is True
    assert is_version_vulnerable("9.3p1", "5.5p1", "9.3p1") is True
    assert is_version_vulnerable("9.3p2", "5.5p1", "9.3p1") is False
    assert is_version_vulnerable("5.4p1", "5.5p1", "9.3p1") is False

    # Curl CVE-2023-38606: 7.69.0 <= ver <= 8.3.0
    assert is_version_vulnerable("7.81.0-1deb11u1", "7.69.0", "8.3.0") is True
    assert is_version_vulnerable("8.3.0", "7.69.0", "8.3.0") is True
    assert is_version_vulnerable("8.4.0", "7.69.0", "8.3.0") is False

    # XZ Backdoor CVE-2024-3094: 5.6.0 <= ver <= 5.6.1
    assert is_version_vulnerable("5.6.0", "5.6.0", "5.6.1") is True
    assert is_version_vulnerable("5.6.1", "5.6.0", "5.6.1") is True
    assert is_version_vulnerable("5.4.5", "5.6.0", "5.6.1") is False

    # Windows CLFS CVE-2023-28252: 10.0.19041 <= ver <= 10.0.20348.1607
    assert is_version_vulnerable("10.0.20348.1607", "10.0.19041", "10.0.20348.1607") is True
    assert is_version_vulnerable("10.0.20348.1668", "10.0.19041", "10.0.20348.1607") is False

def test_phase2_cve_matching_and_deduplication():
    """Verify deduplication when an inventory contains duplicated package declarations."""
    dup_path = os.path.join(FIXTURES_DIR, "duplicate_packages.json")
    with open(dup_path, "r", encoding="utf-8") as f:
        dup_data = json.load(f)

    # Validate duplicate detection in parser
    val = InventoryParser.validate_inventory(dup_data["packages"])
    assert val["duplicate_count"] > 0
    assert len(val["warnings"]) > 0

    # Run CVE detection
    findings = cve_service.find_vulnerabilities("linux", dup_data["packages"])
    cve_ids = [f["cve_id"] for f in findings]

    # Every CVE ID must be completely unique
    assert len(cve_ids) == len(set(cve_ids))
    assert "CVE-2021-4034" in cve_ids
    assert "CVE-2023-44487" in cve_ids

def test_phase2_evidence_storage_and_queries(client, auth_headers):
    """Verify evidence record generation during assessment and retrieval via endpoints."""
    # 1. Create asset & import inventory
    asset_res = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "Evidence Test Server",
        "ip_address": "10.20.1.1",
        "hostname": "evidence-srv-01",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04 LTS"
    })
    asset_id = asset_res.json()["id"]

    inv_path = os.path.join(FIXTURES_DIR, "ubuntu_server_inventory.json")
    with open(inv_path, "r", encoding="utf-8") as f:
        client.post(
            f"/api/v1/assets/{asset_id}/inventory",
            headers=auth_headers,
            data={"raw_content": f.read(), "format_type": "json"}
        )

    # 2. Run assessment
    ass_res = client.post("/api/v1/assessments", headers=auth_headers, json={
        "asset_id": asset_id,
        "title": "Evidence Verification Assessment"
    })
    assert ass_res.status_code == 201
    assessment_id = ass_res.json()["id"]

    # 3. Query vulnerabilities for this assessment
    vulns_res = client.get(f"/api/v1/vulnerabilities?assessment_id={assessment_id}", headers=auth_headers)
    assert vulns_res.status_code == 200
    findings = vulns_res.json()
    assert len(findings) > 0
    finding_id = findings[0]["id"]

    # 4. Query evidence for specific finding
    ev_res = client.get(f"/api/v1/vulnerabilities/{finding_id}/evidence", headers=auth_headers)
    assert ev_res.status_code == 200
    ev_list = ev_res.json()
    assert len(ev_list) >= 1
    ev_item = ev_list[0]
    assert ev_item["finding_id"] == finding_id
    assert "raw_evidence" in ev_item
    assert "evidence_type" in ev_item

    # 5. Query all evidence aggregated for asset
    asset_ev_res = client.get(f"/api/v1/assets/{asset_id}/evidence", headers=auth_headers)
    assert asset_ev_res.status_code == 200
    asset_evidence = asset_ev_res.json()
    assert len(asset_evidence) >= len(findings)

    # Clean up
    client.delete(f"/api/v1/assets/{asset_id}", headers=auth_headers)

def test_phase2_assessment_history_and_comparison(client, auth_headers):
    """Test assessment history listing, before-and-after comparison, and deletion."""
    # 1. Create asset
    asset_res = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "History Compare Server",
        "ip_address": "10.30.1.10",
        "hostname": "history-compare-01",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04 LTS"
    })
    asset_id = asset_res.json()["id"]

    # 2. Import vulnerable inventory & run Assessment 1
    vuln_path = os.path.join(FIXTURES_DIR, "ubuntu_server_inventory.json")
    with open(vuln_path, "r", encoding="utf-8") as f:
        client.post(
            f"/api/v1/assets/{asset_id}/inventory",
            headers=auth_headers,
            data={"raw_content": f.read(), "format_type": "json"}
        )

    ass1_res = client.post("/api/v1/assessments", headers=auth_headers, json={
        "asset_id": asset_id,
        "title": "Baseline Initial Audit"
    })
    assert ass1_res.status_code == 201
    ass1_id = ass1_res.json()["id"]
    ass1_count = ass1_res.json()["findings_count"]
    assert ass1_count >= 3

    # 3. Import patched inventory & run Assessment 2
    patched_path = os.path.join(FIXTURES_DIR, "ubuntu_patched_inventory.json")
    with open(patched_path, "r", encoding="utf-8") as f:
        client.post(
            f"/api/v1/assets/{asset_id}/inventory",
            headers=auth_headers,
            data={"raw_content": f.read(), "format_type": "json"}
        )

    ass2_res = client.post("/api/v1/assessments", headers=auth_headers, json={
        "asset_id": asset_id,
        "title": "Post-Remediation Retest Audit"
    })
    assert ass2_res.status_code == 201
    ass2_id = ass2_res.json()["id"]
    ass2_count = ass2_res.json()["findings_count"]

    # Patched inventory should have far fewer findings
    assert ass2_count < ass1_count

    # 4. Check assessment history listing for this asset
    hist_res = client.get(f"/api/v1/assessments?asset_id={asset_id}", headers=auth_headers)
    assert hist_res.status_code == 200
    history = hist_res.json()
    assert len(history) >= 2

    # 5. Compare assessments
    comp_res = client.get(f"/api/v1/assessments/{ass2_id}/compare/{ass1_id}", headers=auth_headers)
    assert comp_res.status_code == 200
    comp = comp_res.json()
    assert comp["asset_id"] == asset_id
    assert len(comp["resolved_findings"]) > 0
    # Verified resolution of key CVEs
    resolved_cve_ids = [r["cve_id"] for r in comp["resolved_findings"]]
    assert "CVE-2021-4034" in resolved_cve_ids
    assert "CVE-2023-38408" in resolved_cve_ids
    assert comp["findings_count_delta"] < 0
    assert comp["risk_score_delta"] < 0

    # 6. Delete historical assessment
    del_ass = client.delete(f"/api/v1/assessments/{ass2_id}", headers=auth_headers)
    assert del_ass.status_code == 200

    # Clean up
    client.delete(f"/api/v1/assets/{asset_id}", headers=auth_headers)
