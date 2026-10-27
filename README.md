# Vuln TWin — Autonomous Cyber Digital Twin Vulnerability Validation & Remediation Platform

**Vuln TWin** is an end-to-end cybersecurity platform designed for final-year cybersecurity engineering capstone evaluations. It addresses the critical industry challenge of vulnerability prioritization and false-positive fatigue: traditional scanners identify potential theoretical CVEs but cannot verify whether they are genuinely exploitable without risking production damage or operational outages.

Vuln TWin couples **AI/ML risk prioritization** with **isolated Digital Twin sandboxes** to detect vulnerabilities, evaluate composite realized risk, safely validate findings using certified non-destructive test procedures, enforce human sign-off, simulate vendor remediation, and mathematically verify resolution via before-and-after retesting.

---

## Architecture Overview

```
                                  +------------------------------------+
                                  |         Vuln TWin Frontend         |
                                  | React 19 + TypeScript + Tailwind   |
                                  +-----------------+------------------+
                                                    | REST / JWT
                                                    v
+-------------------------------------------------------------------------------------------------------+
|                                        FastAPI Backend Application                                    |
|                                                                                                       |
|  [Auth & RBAC]   [Asset Manager]   [Assessment Engine]   [AI/ML Risk Scorer]   [Reports & Audit]      |
|  - JWT / Bcrypt   - Linux / Windows - Semver Matching     - GradientBoosting   - ReportLab PDF / CSV  |
|  - Role Gates     - JSON / CSV Ingest- Deduplication      - Factor Weights     - Tamper-Resistant Log |
|                                                                                                       |
|                           +-----------------------------------------------+                           |
|                           |             Digital Twin Subsystem            |                           |
|                           | - Provider Adapter (MockIsolated / VBox Stub) |                           |
|                           | - Air-Gapped Network Verification (VLAN 1099) |                           |
|                           | - Snapshot Rollback & Baseline Reset          |                           |
|                           +-----------------------+-----------------------+                           |
|                                                   |                                                   |
|                        +--------------------------+--------------------------+                        |
|                        |                                                     |                        |
|                        v                                                     v                        |
|        [Controlled Validation Lab]                               [Remediation & Retesting]            |
|        - Certified Non-Destructive Probes                        - Human Approval Gate                |
|        - Precondition Enforcer                                   - Safe Execution in Twin Sandbox     |
|        - Outcomes: Confirmed / Not Reproduced                    - Before-and-After Verification      |
+---------------------------------------------------+---------------------------------------------------+
                                                    |
                                                    v
                                  +------------------------------------+
                                  |          Database Storage          |
                                  |    SQLite with Foreign Keys & FK   |
                                  |      Pragma / Transaction Locks    |
                                  +------------------------------------+
```

---

## 13-Step Cybersecurity Demonstration Workflow

The platform implements the following end-to-end cybersecurity workflow:

1. **Authentication**: Register or log in with RBAC role authorization (`admin`, `analyst`, `viewer`).
2. **Asset Registration**: Enroll an authorized target host (e.g., `prod-web-gateway-01` or `win-ad-dc-01`).
3. **Inventory Ingestion**: Import package and configuration metadata from validated JSON or CSV manifests.
4. **CVE Detection & Deduplication**: Evaluate packages against known CVEs accounting for platform applicability and semantic version ranges.
5. **AI/ML Risk Prioritization**: Evaluate realized risk index (0–100) using a trained GradientBoosting model that separates CVSS severity from composite risk.
6. **Digital Twin Replica Creation**: Instantiate an air-gapped sandbox replica with matching OS, packages, and baseline snapshots.
7. **Controlled Validation**: Execute approved non-destructive test procedures (e.g., protocol queries, canary lookups) inside the isolated twin.
8. **Evidence & Verdict Recording**: Record diagnostic telemetry and update finding status to `confirmed` or `inconclusive`.
9. **AI Remediation Recommendation**: Review vendor-supported fix commands, rollback instructions, and prerequisite advisories.
10. **Human-in-the-Loop Sign-Off**: Require explicit human approval and compliance justification before any changes occur.
11. **Isolated Sandbox Patching**: Apply approved vendor fixes strictly inside the designated digital twin replica (production assets remain untouched).
12. **Retest Verification**: Re-collect package versions, re-run detection rules, and re-execute validation probes to confirm remediation.
13. **Executive Reporting**: Download high-resolution PDF dossiers and CSV data sheets with full before-and-after audit logs.

---

## Getting Started & Installation

### Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Node.js 18+ and npm

### Backend Setup
```bash
# Navigate to backend directory
cd backend

# Install Python dependencies
python -m pip install -r requirements.txt

# Start the FastAPI application
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
*Backend API and Swagger UI will be available at:* `http://127.0.0.1:8000/docs`

### Frontend Setup
```bash
# In a new terminal, navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```
*Frontend Cyber Console will be available at:* `http://127.0.0.1:5173`

---

## Automated Test Suite & Complete Verification Results

Comprehensive automated unit, integration, security, and end-to-end regression tests are implemented with `pytest` covering all 8 phases of the cybersecurity platform:

```bash
cd backend
python -m pytest tests/ -v
```

### Full Test Suite Results (53 Passing Tests)
```text
tests/test_all_workflows.py::test_auth_workflow PASSED                   [  1%]
tests/test_all_workflows.py::test_inventory_parser_json PASSED           [  3%]
tests/test_all_workflows.py::test_inventory_parser_csv PASSED            [  5%]
tests/test_all_workflows.py::test_cve_version_matching PASSED            [  7%]
tests/test_all_workflows.py::test_cve_service_deduplication PASSED       [  9%]
tests/test_all_workflows.py::test_ml_risk_engine PASSED                  [ 11%]
tests/test_all_workflows.py::test_digital_twin_lifecycle PASSED          [ 13%]
tests/test_all_workflows.py::test_end_to_end_assessment_validation_remediation_retest PASSED [ 15%]
tests/test_phase1.py::test_phase1_unauthenticated_protected_routes PASSED [ 16%]
tests/test_phase1.py::test_phase1_seeded_admin_and_analyst_logins PASSED [ 18%]
tests/test_phase1.py::test_phase1_role_based_access PASSED               [ 20%]
tests/test_phase1.py::test_phase1_dashboard_structure PASSED             [ 22%]
tests/test_phase2.py::test_phase2_asset_lifecycle PASSED                 [ 24%]
tests/test_phase2.py::test_phase2_inventory_validation_and_json_import PASSED [ 26%]
tests/test_phase2.py::test_phase2_inventory_csv_import_and_headers PASSED [ 28%]
tests/test_phase2.py::test_phase2_cve_semantic_version_range_edge_cases PASSED [ 30%]
tests/test_phase2.py::test_phase2_cve_matching_and_deduplication PASSED  [ 32%]
tests/test_phase2.py::test_phase2_evidence_storage_and_queries PASSED    [ 33%]
tests/test_phase2.py::test_phase2_assessment_history_and_comparison PASSED [ 35%]
tests/test_phase3.py::test_phase3_explainable_baseline_risk_calculation PASSED [ 37%]
tests/test_phase3.py::test_phase3_separation_of_severity_exploitability_and_context PASSED [ 39%]
tests/test_phase3.py::test_phase3_scikit_learn_evaluation_gate PASSED    [ 41%]
tests/test_phase3.py::test_phase3_contributing_factors_and_uncertainty PASSED [ 43%]
tests/test_phase3.py::test_phase3_api_endpoints PASSED                   [ 45%]
tests/test_phase4.py::test_phase4_environment_templates_and_simulation_labels PASSED [ 47%]
tests/test_phase4.py::test_phase4_virtualization_provider_abstraction PASSED [ 49%]
tests/test_phase4.py::test_phase4_twin_records_crud_and_parity_scoring PASSED [ 50%]
tests/test_phase4.py::test_phase4_configuration_comparison PASSED        [ 52%]
tests/test_phase4.py::test_phase4_lifecycle_states_and_snapshot_reset PASSED [ 54%]
tests/test_phase4.py::test_phase4_isolation_verification_enforcement_in_validation PASSED [ 56%]
tests/test_phase4.py::test_phase4_twin_decommission PASSED               [ 58%]
tests/test_phase5.py::test_phase5_procedure_registry_specifications PASSED [ 60%]
tests/test_phase5.py::test_phase5_positive_safe_validation_and_evidence_persistence PASSED [ 62%]
tests/test_phase5.py::test_phase5_negative_safe_validation_not_reproduced PASSED [ 64%]
tests/test_phase5.py::test_phase5_blocked_unapproved_procedure PASSED    [ 66%]
tests/test_phase5.py::test_phase5_blocked_destructive_command_safety PASSED [ 67%]
tests/test_phase5.py::test_phase5_inconclusive_missing_installed_version PASSED [ 69%]
tests/test_phase5.py::test_phase5_inconclusive_component_mismatch PASSED [ 71%]
tests/test_phase6.py::test_phase6_evidence_backed_recommendation_generation PASSED [ 73%]
tests/test_phase6.py::test_phase6_approval_and_rejection_workflows PASSED [ 75%]
tests/test_phase6.py::test_phase6_safe_lab_remediation_adapter_application PASSED [ 77%]
tests/test_phase6.py::test_phase6_production_protection_never_auto_change_production PASSED [ 79%]
tests/test_phase7.py::test_phase7_successful_retest_and_evidence_persistence PASSED [ 81%]
tests/test_phase7.py::test_phase7_failed_retest_unresolved_status PASSED [ 83%]
tests/test_phase7.py::test_phase7_inconclusive_retest_indeterminate_telemetry PASSED [ 84%]
tests/test_phase7.py::test_phase7_inconclusive_retest_scanner_validation_discrepancy PASSED [ 86%]
tests/test_phase7.py::test_phase7_before_after_comparison_endpoint PASSED [ 88%]
tests/test_phase7.py::test_phase7_query_results_and_guardrails PASSED    [ 90%]
tests/test_phase8.py::test_phase8_dashboard_metrics_aggregation PASSED   [ 92%]
tests/test_phase8.py::test_phase8_pdf_reporting_endpoint PASSED          [ 94%]
tests/test_phase8.py::test_phase8_csv_reporting_endpoint PASSED          [ 96%]
tests/test_phase8.py::test_phase8_audit_logs_query_and_filtering PASSED  [ 98%]
tests/test_phase8.py::test_phase8_security_headers_and_unauthenticated_guardrails PASSED [100%]

======================= 53 passed, 1 warning in 13.53s =======================
```

---

## Interactive Capstone Demonstration Walkthrough

Follow these steps to demonstrate the full end-to-end capabilities of Vuln TWin:

### Step 1: Authentication & RBAC Inspection
1. Open `http://localhost:5173` in your browser.
2. Log in using `admin@vulntwin.com` / `VulnTwin@2026!`.
3. Inspect the live metrics dashboard: registered assets, detected CVEs, twin validated counts, and the severity/status breakdown charts.

### Step 2: Asset Management & Manifest Ingestion
1. Navigate to **Assets** (`/assets`).
2. Notice pre-seeded demo assets: *Primary Production Web Gateway* (Ubuntu) and *Domain Controller Staging* (Windows).
3. Click **Import Inventory** on the Ubuntu asset.
4. Upload or paste a package manifest (e.g. `backend/app/fixtures/sample_inventories/ubuntu_server_inventory.json`).
5. Observe the package inventory count update with verified architectures and checksums.

### Step 3: Run Security Assessment & AI/ML Risk Scoring
1. Navigate to **Assessments** (`/assessments`) and click **Execute Assessment**.
2. Select *Primary Production Web Gateway* and submit.
3. Review the completed assessment: average risk score, finding severity counts.
4. Click **Findings** to view detected CVEs (`/vulnerabilities`).
5. Select `CVE-2021-4034` (Polkit pkexec) or `CVE-2023-38408` (OpenSSH).
6. Inspect the AI/ML realized risk gauge (0–100), contributing factor weights, and forensic manifest evidence.

### Step 4: Digital Twin Sandbox Inspection & Isolation Check
1. Navigate to **Digital Twins** (`/twins`).
2. Inspect the sandbox replica for the target asset.
3. Click **Verify Isolation**: observe the airgap telemetry check (VLAN 1099, 0 WAN routes, No production IP overlap).
4. Click **Compare Config** to view configuration parity scoring between production target and twin lab.

### Step 5: Controlled Non-Destructive Validation
1. Navigate to **Validation Lab** (`/validation`).
2. Select finding `CVE-2021-4034` and the isolated twin replica.
3. Execute the certified procedure `PROC-SEC-PKEXEC-01`.
4. Review the diagnostic probe execution: safely queries `argv[0]` bounds without running unconstrained root code.
5. Finding status transitions to **Confirmed**.

### Step 6: Evidence-Backed Remediation & Human Approval
1. Navigate to **Remediation** (`/remediation`).
2. Review the generated recommendation: vendor advisory URL, prerequisites, command preview, and rollback instructions.
3. Under the approval section, select **Approve for Sandbox** and provide compliance justification.
4. Click **Apply in Isolated Twin Sandbox**: the certified adapter applies the upgrade within the isolated twin (`0.105-26` -> `0.105-31.1`).
5. Notice: Production assets remain 100% untouched.

### Step 7: Dual-Verification Retesting
1. Navigate to **Retesting & Verification** (`/retesting`).
2. Select the remediated finding and twin sandbox.
3. Click **Run Retest Verification**:
   - Dynamic twin inspection recollecting package version (`0.105-31.1`).
   - CVE detection rules re-evaluated: **Cleared**.
   - Non-destructive validation probe re-executed: **Mitigated**.
4. Both checks corroborate $\rightarrow$ status becomes **Resolved**, finding marked **Fixed**, and ML risk score drops to **0.0 / Remediated**.
5. View the side-by-side Before-and-After comparative diff.

### Step 8: Executive Reporting & Compliance Audit Trail
1. Return to **Assessments** (`/assessments`).
2. Click the **PDF** icon to download the styled executive report with before/after evidence.
3. Click the **CSV** icon to download structured CSV vulnerability export data.
4. Navigate to **Audit Trail** (`/audit`) to review the immutable audit log tracking every user action, IP, timestamp, and metadata payload.

---

## Quick Demo Accounts

The database is seeded with initial accounts on first launch:

| Role | Email | Password | Permissions |
|---|---|---|---|
| **Administrator** | `admin@vulntwin.com` | `VulnTwin@2026!` | Full administrative access, audit logs, asset deletions, user management |
| **Security Analyst** | `analyst@vulntwin.com` | `SecurePassword123!` | Asset enrollment, scan runs, validation testing, approvals, retests |

---

## Architectural Transparency & Limitations

1. **Virtualization Provider**:
   - The current release uses the `MockIsolatedTwinAdapter` provider, a working, deterministic state-machine simulation enforcing sandbox isolation (VLAN 1099, No WAN gateway, baseline snapshot rollbacks).
   - An adapter interface (`VirtualBoxTwinAdapter`) is prepared for future bare-metal hypervisor linking via `VBoxManage`.
2. **Exploit Safety**:
   - In adherence to strict cybersecurity safety guidelines, the platform never generates or executes arbitrary shell exploits, memory corruption payloads, or weaponized attack code. All validation procedures use certified non-destructive protocol inquiries, symbol verification, or local loopback canary probes.
3. **NVD API Fallback**:
   - When external NIST NVD API keys are not configured or external networks are air-gapped, the engine seamlessly utilizes deterministic offline fixtures covering major Linux and Windows vulnerabilities (`CVE-2021-4034`, `CVE-2023-38408`, `CVE-2021-44228`, `CVE-2023-44487`, `CVE-2023-38606`, `CVE-2023-28252`, `CVE-2024-3094`).
