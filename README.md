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

## Automated Test Execution & Results

Comprehensive automated unit and end-to-end integration tests are implemented with `pytest`:

```bash
cd backend
python -m pytest tests/ -v
```

### Actual Test Results
```text
tests/test_all_workflows.py::test_auth_workflow PASSED                   [ 12%]
tests/test_all_workflows.py::test_inventory_parser_json PASSED           [ 25%]
tests/test_all_workflows.py::test_inventory_parser_csv PASSED            [ 37%]
tests/test_all_workflows.py::test_cve_version_matching PASSED            [ 50%]
tests/test_all_workflows.py::test_cve_service_deduplication PASSED       [ 62%]
tests/test_all_workflows.py::test_ml_risk_engine PASSED                  [ 75%]
tests/test_all_workflows.py::test_digital_twin_lifecycle PASSED          [ 87%]
tests/test_all_workflows.py::test_end_to_end_assessment_validation_remediation_retest PASSED [100%]

======================== 8 passed in 1.82s ========================
```

---

## Quick Demo Accounts

The database is seeded with initial accounts on first launch:

| Role | Email | Password | Permissions |
|---|---|---|---|
| **Administrator** | `admin@vulntwin.com` | `VulnTwin@2026!` | Full administrative access, audit logs, asset deletions |
| **Security Analyst** | `analyst@vulntwin.com` | `SecurePassword123!` | Asset enrollment, scan runs, validation testing, approvals |

---

## Architectural Transparency & Limitations

1. **Virtualization Provider**:
   - The current release uses the `MockIsolatedTwinAdapter` provider, a working, deterministic state-machine simulation enforcing sandbox isolation (VLAN 1099, No WAN gateway, baseline snapshot rollbacks).
   - An adapter interface (`VirtualBoxTwinAdapter`) is prepared for future bare-metal hypervisor linking via `VBoxManage`.
2. **Exploit Safety**:
   - In adherence to strict cybersecurity safety guidelines, the platform never generates or executes arbitrary shell exploits, memory corruption payloads, or weaponized attack code. All validation procedures use certified non-destructive protocol inquiries, symbol verification, or local loopback canary probes.
3. **NVD API Fallback**:
   - When external NIST NVD API keys are not configured or external networks are air-gapped, the engine seamlessly utilizes deterministic offline fixtures covering major Linux and Windows vulnerabilities (`CVE-2021-4034`, `CVE-2023-38408`, `CVE-2021-44228`, `CVE-2023-44487`, `CVE-2023-38606`, `CVE-2023-28252`, `CVE-2024-3094`).
