# VulnTwin AI

VulnTwin AI is an AI-assisted cybersecurity platform that analyzes URLs and security indicators, collects security evidence, calculates explainable risk scores, stores analysis history, and facilitates safe verification of findings inside an isolated Digital Twin lab.

---

## 🏗️ Architecture & Technology Stack

- **Python**: 3.11+ (tested on Python 3.11, 3.12, 3.14)
- **API Framework**: FastAPI
- **ASGI Server**: Uvicorn
- **Data Modeling & Validation**: Pydantic v2 / Pydantic Settings
- **ORM & Database**: SQLAlchemy 2.0 with SQLite (Phase 1 / MVP) → PostgreSQL (Production)
- **Testing**: Pytest & FastAPI TestClient / HTTPX
- **Evidence Collection**: Pluggable Collector Architecture (`BaseCollector`, `CollectorManager`)
- **Analysis Scope**: Purely local passive syntax & hostname analysis (no outbound network requests in Milestone 3)
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
│   │   ├── schemas/
│   │   │   ├── analysis.py                     # Pydantic request & response models (AnalysisResponse, AnalysisDetailResponse)
│   │   │   ├── evidence.py                     # Pydantic models for evidence items & collection status
│   │   │   └── risk.py                         # Pydantic models for deterministic risk, confidence & exploitability
│   │   ├── services/
│   │   │   ├── analysis_service.py             # Lifecycle transitions, evidence persistence & analysis orchestration
│   │   │   ├── collector.py                    # Pluggable BaseCollector interface & safe CollectorManager
│   │   │   ├── passive_analyzer.py             # Non-intrusive syntax and hostname characteristics analyzer
│   │   │   └── risk_engine.py                  # Deterministic, explainable passive risk evaluation engine
│   │   ├── utils/
│   │   │   └── url_validator.py                # Strict URL validation & canonicalization
│   │   └── main.py                             # FastAPI initialization, lifespan & error handlers
│   └── requirements.txt                        # Core project dependencies
├── docs/
│   └── requirements.md                         # Functional & non-functional requirements
├── frontend/                                   # Future React/Tailwind frontend
├── digital-twin/                               # Future containerized lab environments
├── tests/                                      # Automated test suite
│   ├── conftest.py                             # Isolated in-memory DB fixtures & TestClient
│   ├── test_analyses.py                        # Tests for URL submission, validation & DB isolation
│   ├── test_api_v1.py                          # Tests for API info and error handling
│   ├── test_evidence_collector.py              # Tests for passive analyzer & collector error containment
│   ├── test_health.py                          # Tests for health check endpoint
│   └── test_lifecycle_and_risk.py              # Tests for status transitions, risk engine & evidence endpoints
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

### 2. Trigger Passive Evidence Collection & Risk Scoring (Milestone 3)
- **Method**: `POST`
- **Path**: `/api/v1/analyses/{analysis_id}/analyze`
- **Status**: `200 OK` (or `409 Conflict` if the analysis is already completed/failed)

Executes safe, non-intrusive local passive syntax analysis. Enforces valid lifecycle transitions (`pending` → `running` → `completed`), stores evidence items in the database, and produces an explainable risk evaluation.

**PowerShell Example**:
```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/analyses/e4b1bf18-09bc-4340-9a25-e51f28df1d03/analyze"
```

**JSON Response (200 OK)**:
```json
{
  "id": "e4b1bf18-09bc-4340-9a25-e51f28df1d03",
  "url": "https://example.com/login",
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
      "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
      "analysis_id": "e4b1bf18-09bc-4340-9a25-e51f28df1d03",
      "signal_name": "explicit_port",
      "observed_value": null,
      "structured_data": { "default_scheme_port": 443 },
      "evidence_source": "passive_syntax_analyzer",
      "collection_status": "absent",
      "explanatory_notes": "Target URL does not specify an explicit port; default scheme port applies.",
      "observation_timestamp": "2026-10-17T05:00:05Z"
    }
  ],
  "risk_assessment": {
    "risk_score": 20,
    "risk_level": "low",
    "confidence_level": "low",
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
      }
    ],
    "limitations": [
      "Assessment is strictly based on local lexical syntax and hostname characteristics.",
      "No outbound network requests or live target investigations were conducted in this milestone.",
      "Confidence is rated LOW due to the purely syntactic and non-network nature of evidence.",
      "Exploitability is marked UNKNOWN: syntactic signals cannot confirm actionable vulnerability."
    ]
  }
}
```

---

### 3. Retrieve Evidence Observations for an Analysis (Milestone 3)
- **Method**: `GET`
- **Path**: `/api/v1/analyses/{analysis_id}/evidence`
- **Status**: `200 OK`

**PowerShell Example**:
```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8000/api/v1/analyses/e4b1bf18-09bc-4340-9a25-e51f28df1d03/evidence"
```

**JSON Response**:
```json
{
  "analysis_id": "e4b1bf18-09bc-4340-9a25-e51f28df1d03",
  "items": [ ... ],
  "total": 7,
  "observed_count": 6,
  "absent_count": 1,
  "error_count": 0
}
```

---

### 4. Retrieve Saved Analysis Records (Paginated)
- **Method**: `GET`
- **Path**: `/api/v1/analyses?limit=20&offset=0`
- **Status**: `200 OK`

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8000/api/v1/analyses?limit=10&offset=0"
```

---

### 5. Retrieve an Individual Analysis Record
- **Method**: `GET`
- **Path**: `/api/v1/analyses/{analysis_id}`
- **Status**: `200 OK` (or `404 Not Found`)

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8000/api/v1/analyses/e4b1bf18-09bc-4340-9a25-e51f28df1d03"
```

---

## 🔄 Analysis Lifecycle State Machine

```
              ┌─────────┐
              │ PENDING │
              └────┬────┘
                   │
           trigger analysis
                   │
                   ▼
              ┌─────────┐
              │ RUNNING │
              └────┬────┘
                   │
        ┌──────────┴──────────┐
        │                     │
     success                error
        │                     │
        ▼                     ▼
  ┌───────────┐         ┌──────────┐
  │ COMPLETED │         │  FAILED  │
  └───────────┘         └──────────┘
```

- Invalid transitions (such as running analysis again on a `completed` or `failed` record) are rejected with HTTP 409 Conflict.

---

## 🧪 Running Automated Tests

Execute the automated test suite with `pytest`:

```powershell
# From the AutoSecTwin root directory:
python -m pytest -v
```

All 34 automated tests execute in-memory with complete SQLite database isolation.

---

## 🛡️ Safety & Ethical Guidelines

VulnTwin AI is developed strictly for defensive security, educational research, and authorized assessment purposes:
1. **Zero Outbound Network Traffic**: In Milestone 3, all analysis is performed locally on URL strings and hostname syntax. No network packets are sent to target hosts.
2. **Neutral Observations vs. Security Conclusions**: Syntactic features (such as keyword tokens or IP literals) are recorded as factual evidence signals, not as proof that a host is malicious or vulnerable.
3. **Exploitability Strictly UNKNOWN**: Passive inspection cannot determine exploitability. Exploitability defaults to `unknown` until verified in an authorized sandbox.
4. **Collector Fault Tolerance**: Collector failures are contained by `CollectorManager` and recorded as `collection_status: "error"` without halting execution.
5. **No Dangerous Code Execution**: No exploit payloads, malware samples, or arbitrary scripts are executed.
