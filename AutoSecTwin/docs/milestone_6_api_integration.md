# VulnTwin AI — Milestone 6: OS Assessment API Integration Specification & Documentation

## 1. Overview & Architecture

Milestone 6 integrates the defensive, read-only operating system security assessment components developed in Milestones 1–5 into versioned, secure REST API endpoints under `/api/v1/os`.

The architecture enforces strict separation of concerns across:
- **Presentation & Routing**: `app.api.v1.endpoints.os_assessments` mounted in `app.api.v1.router`.
- **Business Orchestration**: `app.services.os_assessment_service`.
- **System Telemetry Probes**: `app.services.os_collectors` (read-only package and security configuration probes).
- **Advisory Matching**: `app.services.os_matcher` (authoritative Ubuntu USN, Debian Security Tracker, and Microsoft MSRC providers).
- **Explainable Risk Engine**: `app.services.os_risk_engine` (deterministic scoring, uncertainty floors, and audit trails).
- **Remediation Planner**: `app.services.os_remediation` (vendor-aligned, unapplied recommendations).
- **Data Persistence**: `app.models.os_asset`, `os_assessment`, `os_evidence`, `os_finding` (SQLAlchemy ORM with SQLite/PostgreSQL compatibility).

---

## 2. API Endpoint Reference

All endpoints are versioned under `/api/v1/os`.

### 2.1 OS Asset Endpoints

#### `POST /api/v1/os/assets`
Registers an assessed host profile with validated metadata.
- **Request Body (`OSAssetCreateRequest`)**:
  ```json
  {
    "host_identifier": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "hostname": "prod-workstation",
    "os_family": "linux",
    "os_name": "Ubuntu 22.04.4 LTS",
    "os_version": "22.04",
    "os_build": "6.5.0-28-generic",
    "architecture": "x86_64"
  }
  ```
- **Response (`201 Created`, `OSAssetResponse`)**:
  ```json
  {
    "id": "7649d214-749e-4c74-9725-b772421ce829",
    "host_identifier": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "hostname": "prod-workstation",
    "os_family": "linux",
    "os_name": "Ubuntu 22.04.4 LTS",
    "os_version": "22.04",
    "os_build": "6.5.0-28-generic",
    "architecture": "x86_64",
    "collected_at": "2026-10-24T16:55:00Z"
  }
  ```

#### `GET /api/v1/os/assets`
Retrieves a paginated list of recorded OS assets.
- **Query Parameters**: `limit` (default: 20, 1-100), `offset` (default: 0).
- **Response (`200 OK`, `OSAssetListResponse`)**:
  ```json
  {
    "items": [...],
    "total": 5,
    "limit": 20,
    "offset": 0
  }
  ```

#### `GET /api/v1/os/assets/{asset_id}`
Retrieves an asset record by UUID. Returns `404 Not Found` if the record does not exist.

---

### 2.2 OS Assessment Lifecycle Endpoints

#### `POST /api/v1/os/assessments`
Initializes a new OS assessment session in `pending` status.
- **Request Body (`OSAssessmentCreateRequest`)**:
  ```json
  {
    "asset_id": "7649d214-749e-4c74-9725-b772421ce829",
    "assessment_type": "local_read_only"
  }
  ```
  *Note: If `asset_id` is omitted, the API automatically detects and links the local machine profile.*
- **Response (`201 Created`, `OSAssessmentResponse`)**:
  ```json
  {
    "id": "5f3a0937-fa4a-4a81-9b19-f52ea28ccb41",
    "asset_id": "7649d214-749e-4c74-9725-b772421ce829",
    "assessment_type": "local_read_only",
    "status": "pending",
    "risk_policy_version": "vulntwin_os_risk_policy_v1",
    "risk_score": null,
    "risk_level": null,
    "confidence_level": null,
    "exploitability_state": "unknown",
    "error_message": null,
    "created_at": "2026-10-24T16:55:10Z",
    "completed_at": null
  }
  ```

#### `GET /api/v1/os/assessments`
Retrieves a paginated list of assessments ordered by `created_at` descending.

#### `GET /api/v1/os/assessments/{assessment_id}`
Retrieves detailed assessment information including asset metadata, collected evidence items, and security findings.
- **Response (`200 OK`, `OSAssessmentDetailResponse`)**:
  ```json
  {
    "id": "5f3a0937-fa4a-4a81-9b19-f52ea28ccb41",
    "asset_id": "7649d214-749e-4c74-9725-b772421ce829",
    "assessment_type": "local_read_only",
    "status": "completed",
    "risk_policy_version": "vulntwin_os_risk_policy_v1",
    "risk_score": 45,
    "risk_level": "high",
    "confidence_level": "high",
    "exploitability_state": "unknown",
    "error_message": null,
    "created_at": "2026-10-24T16:55:10Z",
    "completed_at": "2026-10-24T16:55:14Z",
    "asset": { ... },
    "evidence_items": [ ... ],
    "findings": [ ... ]
  }
  ```

#### `POST /api/v1/os/assessments/{assessment_id}/assess`
Starts execution of an authorized, local, read-only assessment.
- **Workflow**: Transitions `pending` -> `running` -> `completed` (or `failed`).
- **Conflict Handling**: Returns `HTTP 409 Conflict` if the assessment is already in `running`, `completed`, or `failed` state.
- **Error Handling**: Transitions to `failed` and records diagnostic details in `error_message` if required collection probes fail or assessment is materially incomplete.

---

### 2.3 Findings, Evidence, Risk & Remediation Endpoints

#### `GET /api/v1/os/assessments/{assessment_id}/evidence`
Retrieves observed security signals, configuration states, and packages.
- **Response (`200 OK`, `OSEvidenceListResponse`)**:
  ```json
  {
    "assessment_id": "5f3a0937-fa4a-4a81-9b19-f52ea28ccb41",
    "items": [
      {
        "id": "...",
        "collector_name": "linux_dpkg_collector",
        "check_id": "dpkg_installed_packages",
        "signal_name": "installed_package",
        "observed_value": "libc6 2.35-0ubuntu3.1",
        "collection_status": "observed",
        "permission_state": "granted"
      }
    ],
    "total": 12,
    "observed_count": 10,
    "absent_count": 2,
    "unavailable_count": 0,
    "error_count": 0
  }
  ```

#### `GET /api/v1/os/assessments/{assessment_id}/findings`
Retrieves security findings and vulnerabilities with authoritative severity and confidence.
- **Response (`200 OK`, `OSFindingListResponse`)**:
  ```json
  {
    "assessment_id": "5f3a0937-fa4a-4a81-9b19-f52ea28ccb41",
    "items": [
      {
        "id": "...",
        "finding_type": "cve_vulnerability",
        "advisory_id": "CVE-2023-4911",
        "title": "Buffer overflow in dynamic linker (ld.so)",
        "component_name": "libc6",
        "installed_version": "2.35-0ubuntu3.1",
        "fixed_version": "2.35-0ubuntu3.4",
        "cvss_score": 7.8,
        "severity": "critical",
        "confidence": "high",
        "exploitability": "unknown"
      }
    ],
    "total": 1,
    "critical_count": 1,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "unrated_count": 0
  }
  ```

#### `GET /api/v1/os/assessments/{assessment_id}/risk`
Calculates and returns transparent risk scores, rationale, and documented assessment limitations.
- **Response (`200 OK`, `OSRiskEvaluationResult`)**:
  ```json
  {
    "risk_score": 45,
    "risk_level": "high",
    "confidence_level": "high",
    "exploitability_state": "unknown",
    "is_complete": true,
    "vulnerability_subscore": 35.0,
    "misconfiguration_subscore": 10.0,
    "context_subscore": 0.0,
    "uncertainty_adjustment": 0.0,
    "top_contributing_findings": [ ... ],
    "score_rationale": [
      "Vulnerability libc6: CVE-2023-4911 (CRITICAL, CVSS 7.8) contributed 35.0 base points (high confidence, weight=1.00).",
      "Misconfiguration kernel.randomize_va_space (HIGH) contributed 10.0 base points."
    ],
    "limitations": []
  }
  ```

#### `GET /api/v1/os/assessments/{assessment_id}/remediation`
Generates actionable, explainable hardening recommendations.
- **Response (`200 OK`, `OSRemediationPlan`)**:
  ```json
  {
    "assessment_id": "5f3a0937-fa4a-4a81-9b19-f52ea28ccb41",
    "recommendations": [
      {
        "recommendation_id": "REC-001",
        "finding_ref": "CVE-2023-4911",
        "advisory_id": "USN-6409-1",
        "component_name": "libc6",
        "title": "Upgrade libc6 to version 2.35-0ubuntu3.4 or later",
        "rationale": "Installed libc6 version '2.35-0ubuntu3.1' is vulnerable to CVE-2023-4911.",
        "action_category": "package_upgrade",
        "suggested_action": "Upgrade package 'libc6' to version '2.35-0ubuntu3.4' using the official package manager.",
        "security_benefit": "Eliminates CVE-2023-4911 flaw.",
        "operational_impact": "May require service restart or system reboot.",
        "prerequisites": ["Run 'apt update'."],
        "verification_steps": ["Verify installed version >= '2.35-0ubuntu3.4'."],
        "confidence": "high",
        "is_verified_fix": true,
        "is_applied": false,
        "uncertainty_notes": null,
        "documentation_urls": ["https://ubuntu.com/security/notices/USN-6409-1"]
      }
    ],
    "total_recommendations": 1,
    "verified_fix_count": 1,
    "investigation_required_count": 0,
    "remediation_summary": "Remediation plan generated 1 actionable recommendations (1 with confirmed vendor fixes, 0 requiring manual investigation). All recommendations are advisory proposals and have NOT been executed on the host.",
    "limitations": []
  }
  ```

---

## 3. Security, Authorization & Privacy Guarantees

1. **Authorization Boundaries**:
   - Only local read-only assessments (`local_read_only`) are permitted. Arbitrary modes (`remote_shell`, `network_scan`, `active_attack`) are rejected with `HTTP 422` or `HTTP 403`.
   - By default, assessments are restricted to the local host machine. Remote assets require explicit authorization (`X-Asset-Authorized: true`), otherwise rejected with `HTTP 403 Forbidden`.
   - Access control middleware inspects authorization headers, rejecting revoked, unauthorized, or guest roles with `HTTP 403 Forbidden`.

2. **Exploitability Strictly UNKNOWN**:
   - `exploitability` and `exploitability_state` default strictly to `unknown` across all schemas, records, and responses. Active exploit verification is forbidden in this milestone.

3. **Read-Only Non-Destructive Behavior**:
   - No automatic operating system modifications, no package installations, no service restarts, and no execution of remediation recommendations.
   - Every recommendation strictly has `is_applied = False`.
   - No endpoint exists to apply fixes (`/remediate` or `/execute` return `HTTP 404/405`).

4. **Privacy Protection**:
   - Host identifiers use salted SHA-256 hashes (`get_anonymized_host_identifier()`) to prevent leaking raw MAC addresses, hardware serial numbers, or Machine GUIDs.
   - Sensitive credentials, secrets, and auth tokens are excluded from logs and evidence.

5. **Honest Incompleteness & Uncertainty**:
   - Missing inventories or crashed required collection stages trigger `MateriallyIncompleteAssessmentError`, causing the assessment to transition to `failed` rather than reporting false completion.
   - Unreachable advisory feeds or degraded providers apply an uncertainty risk floor (`risk_score >= 30`, `confidence = low`, `is_complete = false`), guaranteeing that missing data is never interpreted as proof of safety.

---

## 4. Supported Platforms & Known Limitations

- **Supported Platforms**:
  - Linux: Ubuntu 20.04+, Debian 11+ (`dpkg` package inventory, `/etc/os-release`, kernel hardening sysctls, sshd config).
  - Windows: Windows 10 (Build 19041+) and Windows 11 (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, installed software registry, Defender Antivirus, Windows Firewall profiles, UAC/RDP NLA).
- **Unsupported Platforms**: macOS (Darwin), FreeBSD, Solaris, and other platforms are rejected with `HTTP 400 Bad Request` or `HTTP 422`.
- **Known Limitations**:
  - Live package querying requires read access to `/var/lib/dpkg/status` on Linux and the Uninstall registry hive on Windows. If permissions are restricted, probes report `unavailable` (`denied`) and apply uncertainty penalties without failing other checks.
