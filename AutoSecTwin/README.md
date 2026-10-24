# VulnTwin AI

VulnTwin AI is an AI-assisted cybersecurity platform that analyzes URLs and security indicators, collects multi-source security evidence, calculates explainable risk scores, stores analysis history, and facilitates safe verification of findings inside an isolated Digital Twin lab.

---

## 🏗️ Architecture & Technology Stack

- **Python**: 3.11+ (compatible with Python 3.11, 3.12, 3.14)
- **API Framework**: FastAPI
- **ASGI Server**: Uvicorn
- **Data Modeling & Validation**: Pydantic v2 / Pydantic Settings
- **ORM & Database**: SQLAlchemy 2.0 with SQLite (Phase 1 / MVP) → PostgreSQL (Production)
- **Testing**: Pytest & FastAPI TestClient / HTTPX
- **Evidence Collection**: Pluggable Collector Architecture (`BaseCollector`, `CollectorManager`)
- **Threat Intelligence**: Pluggable Provider Architecture (`BaseThreatIntelProvider`, `MockThreatIntelProvider`)
- **Analysis Scope**: Purely local passive syntax & hostname analysis + isolated mock threat intelligence (zero outbound network requests to submitted targets)
- **Frontend**: React + Tailwind CSS (Future Phase)
- **Verification Lab**: Isolated Docker containers (Future Phase)

---

## 📁 Project Directory Structure

```
AutoSecTwin/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── endpoints/
│   │   │       │   ├── analyses.py             # Target submission, history, passive analysis & evidence endpoints
│   │   │       │   ├── health.py               # GET /api/v1/health
│   │   │       │   └── info.py                 # GET /api/v1 metadata
│   │   │       └── router.py                   # Aggregated v1 router
│   │   ├── core/
│   │   │   └── config.py                       # App configuration & settings
│   │   ├── db/
│   │   │   └── session.py                      # SQLite engine, SessionLocal, Base & table initialization
│   │   ├── models/
│   │   │   ├── analysis.py                     # SQLAlchemy AnalysisRecord ORM model with lifecycle state machine
│   │   │   └── evidence.py                     # SQLAlchemy SecurityEvidenceRecord ORM model
│   │   ├── providers/
│   │   │   ├── base.py                         # BaseThreatIntelProvider interface & error hierarchy
│   │   │   ├── factory.py                      # Dynamic provider selection factory (Mock vs. VirusTotal)
│   │   │   ├── mock_provider.py                # Deterministic in-memory MockThreatIntelProvider
│   │   │   └── virustotal_provider.py          # Real VirusTotal API v3 provider with privacy filters
│   │   ├── schemas/
│   │   │   ├── analysis.py                     # Pydantic request & response models (AnalysisResponse, AnalysisDetailResponse)
│   │   │   ├── evidence.py                     # Pydantic models for evidence items & collection status
│   │   │   ├── risk.py                         # Pydantic models for deterministic risk, confidence & exploitability
│   │   │   └── threat_intel.py                 # Pydantic models for reputation lookup status and telemetry
│   │   ├── services/
│   │   │   ├── analysis_service.py             # Lifecycle transitions, evidence persistence & analysis orchestration
│   │   │   ├── collector.py                    # Pluggable BaseCollector interface & safe CollectorManager
│   │   │   ├── passive_analyzer.py             # Non-intrusive syntax and hostname characteristics analyzer
│   │   │   ├── risk_engine.py                  # Deterministic, explainable passive risk evaluation engine
│   │   │   └── threat_intel_collector.py       # Adapter integrating threat intelligence into evidence pipeline
│   │   ├── utils/
│   │   │   └── url_validator.py                # Strict URL validation & canonicalization
│   │   └── main.py                             # FastAPI initialization, lifespan & error handlers
│   └── requirements.txt                        # Core project dependencies
├── docs/
│   └── requirements.md                         # Functional & non-functional requirements
├── frontend/                                   # Analysis Results & Evidence Dashboard SPA
│   ├── index.html                              # Semantic HTML5 dashboard layout
│   ├── style.css                               # Bespoke cybersecurity dark theme styling
│   └── app.js                                  # Interactive dashboard SPA logic & API client
├── digital-twin/                               # Future containerized lab environments
├── tests/                                      # Automated test suite (89 tests)
│   ├── conftest.py                             # Isolated in-memory DB fixtures & TestClient
│   ├── test_analyses.py                        # Tests for URL submission, validation & DB isolation
│   ├── test_api_v1.py                          # Tests for API info and error handling
│   ├── test_dashboard_frontend.py              # Tests for dashboard HTML, CSS, JS & detail API
│   ├── test_evidence_collector.py              # Tests for passive analyzer & collector error containment
│   ├── test_health.py                          # Tests for health check endpoint
│   ├── test_lifecycle_and_risk.py              # Tests for status transitions, risk engine & evidence endpoints
│   ├── test_threat_intel.py                    # Tests for threat intel mock provider, error modes & risk scoring
│   └── test_virustotal_provider.py             # Tests for VirusTotal v3 provider, privacy filters & mocked HTTP responses
└── README.md                                   # Setup and execution guide
```

---

## 🚀 Windows Setup and Run Instructions

### 1. Prerequisites
Ensure Python 3.11+ is installed and accessible in your Windows PATH:
```powershell
python --version
```

### 2. Navigate to Project Directory
Open PowerShell or Command Prompt:
```powershell
cd path\to\AutoSecTwin
```

### 3. Create a Virtual Environment (Recommended)
```powershell
python -m venv .venv
```

Activate the virtual environment:
- **PowerShell**:
  ```powershell
  .venv\Scripts\Activate.ps1
  ```
  *(If PowerShell execution policy restricts scripts, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first)*
- **Command Prompt (`cmd`)**:
  ```cmd
  .venv\Scripts\activate.bat
  ```

### 4. Install Dependencies
```powershell
pip install -r backend/requirements.txt
```

---

## 🏃 Running the Development Server

Start the development server using Uvicorn:

```powershell
# From the AutoSecTwin root directory:
python -m uvicorn --app-dir backend app.main:app --reload --host 127.0.0.1 --port 8000
```

Once started, the following interactive documentation and endpoints are available:
- **Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check**: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)
- **API v1 Info**: [http://127.0.0.1:8000/api/v1](http://127.0.0.1:8000/api/v1)

---

## 📡 API Usage & Endpoints

### 1. Submit a Target URL for Analysis
- **Method**: `POST`
- **Path**: `/api/v1/analyses`
- **Status**: `201 Created`

**PowerShell Example**:
```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/analyses" `
  -Headers @{ "Content-Type" = "application/json" } `
  -Body '{"url": "https://example.com/login"}'
```

**JSON Request**:
```json
{
  "url": "https://example.com/login"
}
```

**JSON Response (201 Created)**:
```json
{
  "id": "e4b1bf18-09bc-4340-9a25-e51f28df1d03",
  "url": "https://example.com/login",
  "status": "pending",
  "created_at": "2026-10-17T05:00:00Z",
  "error_message": null
}
```

---

### 2. Trigger Passive Evidence Collection & Risk Scoring (Milestones 3 & 4)
- **Method**: `POST`
- **Path**: `/api/v1/analyses/{analysis_id}/analyze`
- **Status**: `200 OK` (or `409 Conflict` if the analysis is already completed/failed)

Executes safe, non-intrusive local passive syntax analysis and integrated threat intelligence lookups. Enforces valid lifecycle transitions (`pending` → `running` → `completed`), stores evidence items in SQLite, and computes explainable risk evaluation.

**PowerShell Example**:
```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/analyses/e4b1bf18-09bc-4340-9a25-e51f28df1d03/analyze"
```

**JSON Response (200 OK)**:
```json
{
  "id": "e4b1bf18-09bc-4340-9a25-e51f28df1d03",
  "url": "https://malicious-threat.org/auth/login",
  "status": "completed",
  "created_at": "2026-10-17T05:00:00Z",
  "error_message": null,
  "evidence_items": [
    {
      "id": "7b0b6c6b-88d4-42b7-8651-7f9a86b9dc1e",
      "analysis_id": "e4b1bf18-09bc-4340-9a25-e51f28df1d03",
      "signal_name": "url_scheme",
      "observed_value": "https",
      "structured_data": { "scheme": "https", "is_tls_encrypted": true },
      "evidence_source": "passive_syntax_analyzer",
      "collection_status": "observed",
      "explanatory_notes": "Target URL specifies HTTPS with TLS transport encryption.",
      "observation_timestamp": "2026-10-17T05:00:05Z"
    },
    {
      "id": "9c8b7a6d-5e4f-3a2b-1c0d-e5f6a7b8c9d0",
      "analysis_id": "e4b1bf18-09bc-4340-9a25-e51f28df1d03",
      "signal_name": "mock_threat_intel_reputation",
      "observed_value": "malicious",
      "structured_data": {
        "provider": "mock_threat_intel",
        "lookup_status": "match",
        "threat_verdict": "malicious",
        "threat_score": 92,
        "categories": ["phishing", "credential_theft"]
      },
      "evidence_source": "mock_threat_intel",
      "collection_status": "observed",
      "explanatory_notes": "Threat intelligence provider 'mock_threat_intel' returned a confirmed match: verdict='malicious' (score: 92/100, categories: phishing, credential_theft).",
      "observation_timestamp": "2026-10-17T05:00:05Z"
    }
  ],
  "risk_assessment": {
    "risk_score": 60,
    "risk_level": "high",
    "confidence_level": "medium",
    "exploitability": "unknown",
    "contributing_factors": [
      {
        "signal_name": "baseline_system_neutral",
        "score_delta": 10,
        "rationale": "Standard neutral baseline score applied to all submitted targets."
      },
      {
        "signal_name": "url_scheme",
        "score_delta": -5,
        "rationale": "Target URL specifies HTTPS with TLS transport encryption."
      },
      {
        "signal_name": "sensitive_lexical_tokens",
        "score_delta": 15,
        "rationale": "URL path or query string contains authentication-related keywords: 'login'."
      },
      {
        "signal_name": "mock_threat_intel_reputation",
        "score_delta": 40,
        "rationale": "Threat intelligence confirmed malicious reputation entry (malicious)."
      }
    ],
    "limitations": [
      "Assessment is based on local lexical syntax, hostname characteristics, and integrated threat telemetry.",
      "No active target probing, penetration testing, or exploit execution was conducted in this milestone.",
      "A no-match reputation result indicates an absence of known IOCs, not verified safety.",
      "Confidence is calibrated strictly to the breadth of available evidence.",
      "Exploitability is marked UNKNOWN: syntactic signals and external reputation cannot confirm actionable exploitability without sandbox verification."
    ]
  }
}
```

---

### 3. Retrieve Evidence Observations for an Analysis
- **Method**: `GET`
- **Path**: `/api/v1/analyses/{analysis_id}/evidence`
- **Status**: `200 OK`

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8000/api/v1/analyses/e4b1bf18-09bc-4340-9a25-e51f28df1d03/evidence"
```

---

## 🛡️ Threat Intelligence Architecture (Milestones 4 & 5)

### 1. Modular Provider Interface (`BaseThreatIntelProvider`)
The platform decouples threat intelligence providers from API endpoints using an abstract base class. Providers implement:
- `name`: unique provider identifier
- `lookup(indicator, indicator_type)`: queries reputation and returns standardized [`ThreatIntelResult`](file:///c:/Users/prani/.gemini/antigravity-ide/scratch/pvt/AutoSecTwin/backend/app/schemas/threat_intel.py).

### 2. In-Memory Mock Provider (`MockThreatIntelProvider`)
For offline automated testing and zero-configuration development, [`MockThreatIntelProvider`](file:///c:/Users/prani/.gemini/antigravity-ide/scratch/pvt/AutoSecTwin/backend/app/providers/mock_provider.py) operates locally without needing API keys or network requests:
- **Pre-seeded Malicious Targets**: `malicious-threat.org`, `phishing-test.com` (verdict: `malicious`, score: 92/88)
- **Pre-seeded Suspicious Targets**: `suspicious-cdn.org` (verdict: `suspicious`, score: 62)
- **Error Simulation Triggers**:
  - `simulate-timeout` → raises [`ThreatIntelTimeoutError`](file:///c:/Users/prani/.gemini/antigravity-ide/scratch/pvt/AutoSecTwin/backend/app/providers/base.py#L18)
  - `simulate-ratelimit` → raises [`ThreatIntelRateLimitError`](file:///c:/Users/prani/.gemini/antigravity-ide/scratch/pvt/AutoSecTwin/backend/app/providers/base.py#L24)
  - `simulate-invalid-response` → raises [`ThreatIntelInvalidResponseError`](file:///c:/Users/prani/.gemini/antigravity-ide/scratch/pvt/AutoSecTwin/backend/app/providers/base.py#L30)
  - `simulate-unavailable` → raises [`ThreatIntelUnavailableError`](file:///c:/Users/prani/.gemini/antigravity-ide/scratch/pvt/AutoSecTwin/backend/app/providers/base.py#L36)
- **Clean / Unlisted Targets**: Returns `lookup_status: "no_match"`.

### 3. Real Threat Intelligence Provider: VirusTotal v3 (`VirusTotalProvider`)
Milestone 5 introduces real threat reputation telemetry via the official **VirusTotal API v3** ([`VirusTotalProvider`](file:///c:/Users/prani/.gemini/antigravity-ide/scratch/pvt/AutoSecTwin/backend/app/providers/virustotal_provider.py)):
- **API Specification**: Uses standard URL reputation lookup (`GET /api/v3/urls/{url_id}`), where `url_id` is computed via Base64url encoding without trailing padding characters (`=`).
- **Reputation Lookup Only**: No active scanning or HTTP requests are ever made to the submitted target URL itself. Only pre-existing third-party threat engine telemetry is retrieved from VirusTotal.
- **Provider Selection & Configuration**: Configured strictly via environment variables. API keys are never hardcoded or logged:
  ```powershell
  # Windows PowerShell
  $env:THREAT_INTEL_PROVIDER="virustotal"
  $env:VT_API_KEY="your_virustotal_api_key_here"
  $env:THREAT_INTEL_TIMEOUT_SECONDS="4.0"
  $env:THREAT_INTEL_WARN_EXTERNAL="true"
  ```
  ```bash
  # Linux / macOS / Bash
  export THREAT_INTEL_PROVIDER="virustotal"
  export VT_API_KEY="your_virustotal_api_key_here"
  export THREAT_INTEL_TIMEOUT_SECONDS=4.0
  export THREAT_INTEL_WARN_EXTERNAL=true
  ```
- **Failing Safely on Missing Key**:
  When `THREAT_INTEL_PROVIDER="virustotal"` is configured without `VT_API_KEY`, the platform does **not** silently fake a mock result. The provider fails clearly and safely with a structured `ThreatIntelAuthError`, recorded in evidence as `error_auth_error` without crashing the analysis.
- **Returning to Mock Mode**:
  To return to offline mock mode at any time, unset `VT_API_KEY` or set:
  ```powershell
  $env:THREAT_INTEL_PROVIDER="mock"
  ```

### 4. Distinct Lookup Outcomes & Semantics
The platform preserves and distinguishes seven distinct lookup outcomes:
1. **Confirmed Match (`match`)**: Multi-vendor security engines flag the indicator as malicious or suspicious. Elevates risk score and confidence.
2. **Genuine No-Match (`no_match`)**: Target was scanned by multi-vendor engines with zero malicious or suspicious detections (HTTP 200). `score_delta` is strictly `+0`.
3. **Unknown Indicator (`unknown_indicator`)**: Target has never been submitted or recorded in the provider database (HTTP 404 `NotFoundError`). Documented VirusTotal API semantics are preserved. An unknown indicator is strictly distinct from a clean result; `score_delta` is `+0`.
4. **Privacy-Blocked (`privacy_blocked`)**: Target contains private IP, loopback, internal hostname, or embedded credentials. Intercepted locally; zero outbound packets are sent. Recorded as `collection_status="skipped"`. **Never reported as a clean result.**
5. **Authentication Error (`auth_error`)**: Missing or invalid API key (HTTP 401/403). Recorded as collector error evidence item without stopping the pipeline.
6. **Rate-Limited (`rate_limited`)**: Provider quota exceeded (HTTP 429). Recorded as collector error evidence item.
7. **Timeout & Provider Outage (`timeout` / `unavailable`)**: Socket timeout or HTTP 5xx service outage. Safely handled without breaking the analysis lifecycle.

### 5. Privacy Safeguards & External Transmission Disclosures
- **Automatic Private / Internal Target Filter**:
  Before any external request is made, [`is_private_or_internal_indicator`](file:///c:/Users/prani/.gemini/antigravity-ide/scratch/pvt/AutoSecTwin/backend/app/providers/virustotal_provider.py#L74) inspects the target:
  - **Loopback IPs & Localhost**: `127.0.0.0/8`, `::1`, `localhost`, `ip6-localhost`
  - **RFC 1918 Private IPv4**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - **RFC 4193 Unique Local IPv6**: `fc00::/7`
  - **Link-Local Addresses**: `169.254.0.0/16`, `fe80::/10`
  - **Decimal/Numeric IPv4 Representations**: e.g., `2130706433` (`127.0.0.1`)
  - **Local Hostnames & Internal TLDs**: `.local`, `.internal`, `.lan`, `.corp`, `.home`, `.test`, `.home.arpa`
  - **Embedded User Credentials**: URLs containing `username:password@hostname`
  - When detected, the lookup is **aborted locally** with zero network traffic.
- **Redirection Hardening**: HTTP client explicitly sets `follow_redirects=False` to prevent redirect-based request hijacking.
- **Credential & Secret Redaction in Logs**:
  All log messages and audit entries sanitize targets using [`sanitize_indicator_for_logging`](file:///c:/Users/prani/.gemini/antigravity-ide/scratch/pvt/AutoSecTwin/backend/app/providers/virustotal_provider.py#L46), redacting passwords (`***:***@...`) so sensitive credentials are never stored in logs or API responses.
- **Third-Party Disclosure Warning**:
  Querying external threat intelligence services discloses the submitted indicator to VirusTotal. External lookups should only be performed on public indicators.

### 6. Analytical & Safety Invariants
1. **Absence is NOT Innocence**: When a provider returns `no_match` or `unknown_indicator`, the score delta is strictly `+0`. The risk score is **never** decreased for an unlisted target.
2. **Reputation is NOT Proof of Exploitability**: External reputation scores reflect consensus threat telemetry, but do **not** confirm that a target has actionable vulnerabilities or is exploitable. Exploitability remains strictly `unknown` until actively verified inside an isolated Digital Twin sandbox.
3. **Confidence Calibration**: A corroborated match elevates confidence to `medium` (from `low`), reflecting multiple independent evidentiary sources.
4. **Reputation Lookup Only**: Zero network packets are ever transmitted to arbitrary user-supplied target indicators.

---

## 🖥️ Evidence & Analysis Dashboard (Milestone 6)

Milestone 6 introduces a responsive, zero-build Single-Page Application (SPA) dashboard located in `frontend/` and served directly by FastAPI at `/dashboard`.

### Features & Capabilities
1. **Indicator Submission & Workflow**:
   - Single-click target submission with quick-test presets (Public Benign, Threat Match, Loopback IP, Credentials & Internal, Unknown Indicator).
   - Prominent **Privacy & Threat Intelligence Disclosure Banner** warning that public queries may disclose indicators to third-party databases.
   - Real-time lifecycle visualization: auto-submits target (`pending`) and triggers passive analysis pipeline (`running` → `completed`).
2. **Real-Time Overview Metrics**:
   - Total Analyses, Completed Analyses, Pending Analyses, and Failed Analyses calculated directly from live API data.
3. **Core Assessment Triad**:
   - **Deterministic Risk Score**: Visual gauge (0–100) with categorical level badges (Low, Medium, High, Critical) and transparent point breakdown per contributing factor.
   - **Confidence Level**: Calibrated to evidence breadth (`low` for syntax only, `medium` for corroborated threat telemetry).
   - **Exploitability Status**: Fixed at `UNKNOWN` with a prominent safety disclaimer: *Reputation findings do not assert verified exploitability without sandbox testing.*
4. **Threat Intelligence Outcome Banner**:
   - Visually differentiates:
     - 🔴 **Confirmed Threat Match**: Malicious / Suspicious multi-vendor detection.
     - 🟢 **Genuine No-Match (Clean in DB)**: Zero detections with *absence is not innocence* notice.
     - ⚪ **Unknown Indicator**: Unrecorded in database (HTTP 404). Strictly not labeled as safe.
     - 🟣 **Privacy-Blocked Lookup**: Loopbacks, RFC 1918 IPs, internal hostnames, and credentials intercepted locally with `collection_status="skipped"`.
     - 🟠 **Provider Error / Rate Limited**: Quota or connection issues safely handled.
5. **Interactive Evidence Table & Filtering**:
   - Filter evidence observations by status: *All*, *Observed*, *Absent*, *Skipped (Privacy)*, and *Error*.
   - Displays signal name, observed value, evidence source, and explanatory notes.
6. **Defensive Remediation Guidance**:
   - Actionable, practical hardening suggestions based on observed evidence (TLS enforcement, authentication hardening, IOC investigation, perimeter defense) without claiming unverified vulnerabilities.
7. **Analysis History & Filtering**:
   - Searchable by target URL or analysis ID.
   - Filterable by status (All, Completed, Pending, Failed).
   - Detailed inspection drawer with reload and re-analyze capabilities.

### Accessing the Dashboard
Start the Uvicorn development server:
```powershell
python -m uvicorn --app-dir backend app.main:app --host 127.0.0.1 --port 8000
```
Open your browser and navigate to:
**[http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)**

---

## 🛡️ Operating System Security Assessment API (Milestone 6)

Milestone 6 exposes the read-only, non-destructive OS assessment pipeline via versioned REST API endpoints under `/api/v1/os`.

### Endpoints Overview
- **Asset Registration & Query**:
  - `POST /api/v1/os/assets`: Register an assessed OS asset profile (`OSAssetCreateRequest`).
  - `GET /api/v1/os/assets`: List registered OS asset profiles with pagination (`limit`, `offset`).
  - `GET /api/v1/os/assets/{asset_id}`: Retrieve a specific OS asset profile by UUID.
- **Assessment Lifecycle**:
  - `POST /api/v1/os/assessments`: Create a new assessment session (`pending`). If `asset_id` is omitted, auto-discovers local host.
  - `GET /api/v1/os/assessments`: List assessment sessions with pagination.
  - `GET /api/v1/os/assessments/{assessment_id}`: Retrieve detailed assessment state, asset metadata, evidence, and findings.
  - `POST /api/v1/os/assessments/{assessment_id}/assess`: Execute authorized local read-only assessment (`pending` → `running` → `completed`).
- **Telemetry, Findings, Risk & Remediation**:
  - `GET /api/v1/os/assessments/{assessment_id}/evidence`: Retrieve collected security evidence and status counts (`observed`, `absent`, `unavailable`, `error`).
  - `GET /api/v1/os/assessments/{assessment_id}/findings`: Retrieve security findings and vulnerabilities with authoritative severity and confidence.
  - `GET /api/v1/os/assessments/{assessment_id}/risk`: Retrieve transparent composite risk scores (0–100), scoring rationale, subscores, and documented assessment limitations.
  - `GET /api/v1/os/assessments/{assessment_id}/remediation`: Retrieve explainable, recommendation-only remediation plans (`is_applied` is strictly `False`).

### Defensive Guarantees
- **Strictly Local / Authorized**: Remote targets require explicit authorization; unauthorized modes (`remote_shell`, `active_attack`) are rejected.
- **Read-Only**: Zero system modifications, patch installations, or service restarts.
- **Exploitability UNKNOWN**: Exploitability defaults strictly to `unknown` across all schemas.
- **Uncertainty Over False Clean**: Missing inventories or unavailable feeds trigger uncertainty floors rather than a false clean score.

---

## 🧪 Running Automated Tests

Execute the automated test suite with `pytest`:

```powershell
# From the AutoSecTwin root directory:
python -m pytest -v
```

All **249 automated tests** execute in-memory with complete SQLite database isolation. External HTTP calls are 100% mocked with deterministic fixtures, ensuring zero external network traffic or host modifications during test runs.
