# VulnTwin AI: Project Requirements Specification (MVP)

## 1. Project Overview & Purpose

**VulnTwin AI** is an AI-assisted cybersecurity analysis platform designed for security researchers, analysts, and DevSecOps practitioners. The platform systematically analyzes URLs and security indicators, collects multi-source security evidence, calculates explainable and transparent risk scores, maintains a searchable history of analysis runs, and enables safe verification of selected security findings within an isolated Digital Twin lab.

---

## 2. System Architecture & Tech Stack

- **Backend Framework**: Python 3.11+ / FastAPI (high-performance asynchronous API)
- **ASGI Server**: Uvicorn
- **Data Modeling & Validation**: Pydantic v2 / Pydantic Settings
- **Testing & Quality Assurance**: Pytest, FastAPI TestClient / HTTPX
- **Data Persistence**:
  - *Phase 1 / MVP*: SQLite (zero-configuration local persistence)
  - *Production*: PostgreSQL
- **Frontend (Future Phase)**: React with Tailwind CSS
- **Isolated Lab (Future Phase)**: Docker containerized sandboxes with restricted network namespaces

---

## 3. MVP Functional Requirements (FR)

### FR-1: System Health, Discovery & Metadata (Milestone 1)
- **FR-1.1**: The platform must expose `GET /api/v1/health` returning application name, operational status, and active API version.
- **FR-1.2**: The platform must expose `GET /api/v1` returning API metadata, documentation endpoints (`/docs`, `/redoc`), and version specifications.
- **FR-1.3**: The system must provide input-independent error envelopes for 404, 422, and 500 error scenarios without exposing internal implementation details or stack traces to clients.

### FR-2: Indicator Ingestion & Normalization (Upcoming Milestone)
- **FR-2.1**: Ingestion and validation of target indicators (fully qualified domain names, URLs, IP addresses) via strict schema validation.
- **FR-2.2**: Canonical normalization of indicators (de-duplication, schema extraction, sanitization) to avoid duplicate analysis pipelines.

### FR-3: Passive Security Evidence Gathering (Upcoming Milestone)
- **FR-3.1**: Collect passive security signals (DNS records, SSL/TLS certificate chain details, HTTP security headers, WHOIS metadata) using non-intrusive protocols.
- **FR-3.2**: Enforce strict safety boundaries: no arbitrary active penetration testing, no unauthorized port scanning, and no exploit payloads during passive analysis.

### FR-4: Explainable Risk Scoring Engine (Upcoming Milestone)
- **FR-4.1**: Compute deterministic and explainable risk scores based on weighted security evidence.
- **FR-4.2**: Every generated score must be broken down into contributing factors (e.g., missing security headers, expired certificates, suspicious TLDs, domain age) with individual weightings.
- **FR-4.3**: Categorical confidence levels and risk ratings (Low, Medium, High, Critical) must accompany raw scores.

### FR-5: Persistent History & Analysis Run Tracking (Upcoming Milestone)
- **FR-5.1**: Persist each analysis run, including input indicator, gathered evidence snapshots, calculated score, and execution timestamps.
- **FR-5.2**: Provide queryable endpoints for historical runs, status lookups, and comparative delta analyses.

### FR-6: Isolated Digital Twin Verification Lab (Future Phase)
- **FR-6.1**: Provide reproducible containerized Digital Twin environments to safely simulate target configurations without touching external production infrastructure.
- **FR-6.2**: Execute isolated verification tests under strictly segregated Docker networks.

---

## 4. Non-Functional Requirements (NFR)

### NFR-1: Safety & Ethical Compliance
- The system must adhere to strict defensive cybersecurity principles.
- Active target scanning and penetration testing must never be performed against unvetted external targets.
- No malicious code, trojans, or exploit artifacts may be executed outside the designated, sandboxed Digital Twin environment.

### NFR-2: Performance & Scalability
- Health and metadata endpoints must maintain latency under 50ms at P95 under standard development loads.
- Asynchronous non-blocking I/O (`async`/`await`) must be utilized for all network-bound evidence collection operations.

### NFR-3: Reliability & Error Handling
- All endpoints must return standard JSON response envelopes on errors (`status_code`, `error`, `message`, `path`).
- Unhandled server exceptions must return HTTP 500 with generic safe descriptions while logging diagnostic details server-side.

### NFR-4: Auditability & Explainability
- Risk scores must never be black-box outputs. Each score must produce an audit trail containing the exact formulas, rule triggers, and evidentiary data points.

### NFR-5: Maintainability & Code Quality
- Strict type hinting across all Python modules.
- Modular architecture with clean separation of concerns: `core/`, `api/`, `models/`, `services/`, and `db/`.
- Automated test coverage with pytest across all endpoints and business logic.
